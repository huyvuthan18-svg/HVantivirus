#define UNICODE
#define _UNICODE

#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include <process.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cwctype>
#include <cctype>

namespace fs = std::filesystem;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

static HINSTANCE g_inst = nullptr;
static HWND g_main = nullptr;
static HWND g_status = nullptr;
static HWND g_progress = nullptr;
static HWND g_progressText = nullptr;
static HWND g_results = nullptr;
static HWND g_filesText = nullptr;
static HWND g_threatsText = nullptr;
static HWND g_guardText = nullptr;
static HWND g_lastScanText = nullptr;
static HWND g_quarantineBtn = nullptr;
static HWND g_cancelBtn = nullptr;
static HWND g_quickBtn = nullptr;
static HWND g_fullBtn = nullptr;
static HWND g_customBtn = nullptr;
static HWND g_processBtn = nullptr;
static HWND g_guardBtn = nullptr;
static HWND g_fileBtn = nullptr;
static HWND g_dropHint = nullptr;

static std::atomic<bool> g_scanning(false);
static std::atomic<bool> g_cancelScan(false);
static std::atomic<bool> g_guardRunning(false);
static std::thread g_scanThread;
static std::thread g_guardThread;
static std::mutex g_dataMutex;

struct Detection {
    std::wstring path;
    std::wstring reason;
    int score = 0;
    bool quarantineable = false;
    std::wstring sha256;
};

struct ScanStats {
    std::atomic<unsigned long long> files{0};
    std::atomic<unsigned long long> suspicious{0};
    std::atomic<unsigned long long> threats{0};
    std::atomic<unsigned long long> errors{0};
};

static ScanStats g_stats;
static std::vector<Detection> g_detections;
static std::wstring g_lastScan;
static std::map<std::wstring, FILETIME> g_guardSnapshot;
static std::map<std::wstring, std::wstring> g_hashDefinitions;
static bool g_forceHashScan = false;
static std::wstring g_singleScanPath;
static std::wstring g_singleScanHash;

static const wchar_t* APP_NAME = L"HVantivirus";
static const wchar_t* APP_DIR = L"HVantivirus";
static const UINT WM_SCAN_PROGRESS = WM_APP + 10;
static const UINT WM_SCAN_FINISHED = WM_APP + 11;
static const UINT WM_GUARD_HIT = WM_APP + 12;

static std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

static bool EndsWith(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    return Lower(s.substr(s.size() - suffix.size())) == Lower(suffix);
}

static std::wstring NowString() {
    SYSTEMTIME st{}; GetLocalTime(&st);
    wchar_t b[64];
    swprintf_s(b, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

static std::wstring LocalAppDataDir() {
    wchar_t p[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, p)))
        return std::wstring(p) + L"\\" + APP_DIR;
    return L".";
}

static std::wstring QuarantineDir() {
    return LocalAppDataDir() + L"\\Quarantine";
}

static void EnsureDirectories() {
    std::error_code ec;
    fs::create_directories(fs::path(QuarantineDir()), ec);
}


static std::wstring AppDirectory() {
    wchar_t path[32768]{};
    DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
    if (!n) return L".";
    return fs::path(std::wstring(path, n)).parent_path().wstring();
}

static void LoadHashDefinitions() {
    g_hashDefinitions.clear();
    fs::path defs = fs::path(AppDirectory()) / L"definitions.txt";
    if (!fs::exists(defs)) {
        std::wofstream out(defs);
        out << L"# SHA256|reason\n";
        out << L"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f|EICAR antivirus test file\n";
        return;
    }
    std::wifstream in(defs);
    std::wstring line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == L'#') continue;
        size_t sep = line.find(L'|');
        if (sep == std::wstring::npos) continue;
        std::wstring hash = Lower(line.substr(0, sep));
        std::wstring reason = line.substr(sep + 1);
        if (hash.size() == 64 && !reason.empty()) g_hashDefinitions[hash] = reason;
    }
}

static std::optional<std::wstring> LookupHashDefinition(const std::wstring& hash) {
    if (hash.empty()) return std::nullopt;
    auto it = g_hashDefinitions.find(Lower(hash));
    if (it == g_hashDefinitions.end()) return std::nullopt;
    return it->second;
}

static std::wstring FileNameOnly(const std::wstring& p) {
    try { return fs::path(p).filename().wstring(); } catch (...) { return p; }
}

static bool IsDangerousExt(const std::wstring& p) {
    static const wchar_t* exts[] = {
        L".exe",L".scr",L".com",L".pif",L".bat",L".cmd",L".ps1",L".vbs",L".vbe",L".js",L".jse",L".hta",L".wsf",L".wsh",L".msi",L".dll"
    };
    std::wstring lp = Lower(p);
    for (auto e : exts) if (EndsWith(lp, e)) return true;
    return false;
}

static bool LooksLikeDoubleExtension(const std::wstring& p) {
    static const wchar_t* decoys[] = { L".pdf.exe",L".doc.exe",L".docx.exe",L".xls.exe",L".xlsx.exe",L".jpg.exe",L".jpeg.exe",L".png.exe",L".txt.exe",L".zip.exe",L".rar.exe",L".jpg.scr",L".png.scr",L".pdf.scr" };
    std::wstring lp = Lower(p);
    for (auto d : decoys) if (lp.find(d) != std::wstring::npos) return true;
    return false;
}

static bool IsUserHotFolder(const std::wstring& p) {
    std::wstring lp = Lower(p);
    return lp.find(L"\\downloads\\") != std::wstring::npos ||
           lp.find(L"\\desktop\\") != std::wstring::npos ||
           lp.find(L"\\appdata\\local\\temp\\") != std::wstring::npos;
}

static bool ReadSample(const fs::path& p, std::string& data, size_t maxBytes = 8 * 1024 * 1024) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    data.resize(maxBytes);
    f.read(data.data(), (std::streamsize)data.size());
    data.resize((size_t)f.gcount());
    return true;
}

static double Entropy(const std::string& s) {
    if (s.empty()) return 0.0;
    unsigned long long count[256]{};
    for (unsigned char c : s) ++count[c];
    double h = 0.0;
    const double n = (double)s.size();
    for (auto c : count) if (c) {
        double p = c / n;
        h -= p * log2(p);
    }
    return h;
}


static std::wstring HexLower(const unsigned char* data, size_t size) {
    static const wchar_t* hex = L"0123456789abcdef";
    std::wstring out; out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) { out.push_back(hex[data[i] >> 4]); out.push_back(hex[data[i] & 0x0F]); }
    return out;
}

static std::wstring Sha256File(const fs::path& path) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCRYPT_HASH_HANDLE* ph = &hash;
    std::wstring result;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return result;
    DWORD objLen = 0, cb = 0, hashLen = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) != 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return result;
    }
    std::vector<unsigned char> obj(objLen), digest(hashLen), buffer(1024 * 1024);
    if (BCryptCreateHash(alg, ph, obj.data(), objLen, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return result;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0); return result; }
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = in.gcount();
        if (got > 0 && BCryptHashData(hash, buffer.data(), static_cast<ULONG>(got), 0) != 0) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0); return result;
        }
    }
    if (BCryptFinishHash(hash, digest.data(), hashLen, 0) == 0) result = HexLower(digest.data(), digest.size());
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0);
    return result;
}

static std::wstring BuildReason(const std::wstring& title, const std::vector<std::wstring>& why) {
    std::wstring reason = title;
    for (size_t i = 0; i < why.size(); ++i) reason += (i == 0 ? L": " : L", ") + why[i];
    return reason;
}

static bool IsEicar(const std::string& data) {
    const std::string sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    return data.find(sig) != std::string::npos;
}

static int CountInsensitive(const std::string& a, const std::string& needle) {
    if (needle.empty() || a.empty()) return 0;
    std::string s = a, n = needle;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    int count = 0; size_t pos = 0;
    while ((pos = s.find(n, pos)) != std::string::npos) { ++count; pos += n.size(); }
    return count;
}

static std::optional<Detection> AnalyzeFile(const fs::path& path, bool forceHash = false) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec) || ec) return std::nullopt;
    auto size = fs::file_size(path, ec);
    if (ec || size == 0) return std::nullopt;

    const std::wstring wp = path.wstring();
    std::string data;
    const bool needHash = forceHash || IsDangerousExt(wp) || IsUserHotFolder(wp);
    if (needHash) {
        std::wstring hash = Sha256File(path);
        if (auto known = LookupHashDefinition(hash)) {
            return Detection{wp, L"Known SHA-256 signature: " + *known, 100, true, hash};
        }
    }

    // Strong, harmless test signature.
    if (ReadSample(path, data, (size_t)std::min<unsigned long long>(size, 8ULL * 1024 * 1024)) && IsEicar(data)) {
        return Detection{wp, L"EICAR antivirus test signature", 100, true, Sha256File(path)};
    }

    int score = 0;
    std::vector<std::wstring> why;
    if (LooksLikeDoubleExtension(wp)) { score += 5; why.push_back(L"deceptive double extension"); }
    if (IsDangerousExt(wp)) { score += 1; }
    if (IsUserHotFolder(wp)) { score += 1; }

    // Inspect scripts and executable-like files. Larger files are sampled for speed.
    bool inspect = IsDangerousExt(wp) || IsUserHotFolder(wp);
    if (inspect) {
        if (data.empty() && !ReadSample(path, data)) return std::nullopt;
        const char* suspicious[] = {
            "powershell -enc", "powershell.exe -enc", "-encodedcommand", "frombase64string",
            "wscript.shell", "scripting.filesystemobject", "mshta.exe", "rundll32.exe",
            "regsvr32.exe", "certutil -decode", "bitsadmin", "schtasks /create", "createobject(\"wscript.shell\")",
            "downloadstring", "invoke-webrequest", "iex(", "cmd.exe /c", "http://", "https://"
        };
        int hits = 0;
        for (auto x : suspicious) if (CountInsensitive(data, x)) { ++hits; why.push_back(L"suspicious command/string"); }
        score += std::min(hits * 3, 12);

        // Very high entropy is only a weak indicator; use it as a supporting signal.
        if (data.size() >= 32768 && Entropy(data.substr(0, std::min<size_t>(data.size(), 65536))) > 7.65) {
            score += 2; why.push_back(L"high-entropy payload region");
        }

        if (data.size() >= 2 && (unsigned char)data[0] == 'M' && (unsigned char)data[1] == 'Z') {
            // PE file + suspicious script-like strings is stronger.
            if (hits >= 1) { score += 2; why.push_back(L"PE executable with suspicious strings"); }
        }
    }

    if (score >= 7) {
        std::wstring reason = L"Heuristic detection";
        for (size_t i=0;i<why.size();++i) { reason += (i==0?L": ":L", ") + why[i]; }
        return Detection{wp, reason, score, true, Sha256File(path)};
    }
    if (score >= 4) {
        std::wstring reason = L"Suspicious file";
        for (size_t i=0;i<why.size();++i) { reason += (i==0?L": ":L", ") + why[i]; }
        return Detection{wp, reason, score, true, Sha256File(path)};
    }
    return std::nullopt;
}

static void ResetStats() {
    g_stats.files = 0; g_stats.suspicious = 0; g_stats.threats = 0; g_stats.errors = 0;
    std::lock_guard<std::mutex> lk(g_dataMutex); g_detections.clear();
}

static std::vector<fs::path> CollectFiles(const std::vector<fs::path>& roots) {
    std::vector<fs::path> out;
    std::error_code ec;
    for (const auto& root : roots) {
        if (g_cancelScan) break;
        if (!fs::exists(root, ec)) { ec.clear(); continue; }
        if (fs::is_regular_file(root, ec)) { out.push_back(root); ec.clear(); continue; }
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end && !g_cancelScan; it.increment(ec)) {
            if (ec) { ++g_stats.errors; ec.clear(); continue; }
            std::error_code te;
            if (it->is_regular_file(te) && !te) out.push_back(it->path());
        }
    }
    return out;
}

static void PushDetection(const Detection& d) {
    std::lock_guard<std::mutex> lk(g_dataMutex);
    g_detections.push_back(d);
}

static void WorkerScan(const std::vector<fs::path>& files, bool showEveryFile=false, bool forceHash=false) {
    const size_t total = files.size();
    for (size_t i=0; i<total && !g_cancelScan; ++i) {
        auto d = AnalyzeFile(files[i], forceHash);
        ++g_stats.files;
        if (d) {
            if (d->score >= 7) ++g_stats.threats; else ++g_stats.suspicious;
            PushDetection(*d);
        }
        if (showEveryFile || i % 12 == 0 || i + 1 == total) {
            auto* p = new unsigned long long[2]{(unsigned long long)(i+1),(unsigned long long)total};
            PostMessageW(g_main, WM_SCAN_PROGRESS, 0, (LPARAM)p);
        }
    }
}

static void BeginScan(const std::vector<fs::path>& roots, const std::wstring& title, bool forceHash=false) {
    if (g_scanning) return;
    ResetStats();
    g_cancelScan = false;
    g_scanning = true;
    g_forceHashScan = forceHash;
    g_singleScanPath.clear(); g_singleScanHash.clear();
    if (roots.size() == 1) { std::error_code sec; if (fs::is_regular_file(roots[0], sec) && !sec) g_singleScanPath = roots[0].wstring(); }
    EnableWindow(g_cancelBtn, TRUE);
    EnableWindow(g_quarantineBtn, FALSE);
    SetWindowTextW(g_status, title.c_str());
    SetWindowTextW(g_progressText, L"Preparing file list...");
    SendMessageW(g_progress, PBM_SETPOS, 0, 0);
    SetWindowTextW(g_quickBtn, L"Quick Scan");

    g_scanThread = std::thread([roots]() {
        auto files = CollectFiles(roots);
        PostMessageW(g_main, WM_SCAN_PROGRESS, 1, 0);
        WorkerScan(files, false, g_forceHashScan);
        if (g_forceHashScan && files.size() == 1) g_singleScanHash = Sha256File(files[0]);
        PostMessageW(g_main, WM_SCAN_FINISHED, 0, 0);
    });
}

static void StartQuickScan() {
    wchar_t p[MAX_PATH]{};
    std::vector<fs::path> roots;
    auto addKnown = [&](int csidl) {
        if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, p))) roots.emplace_back(p);
    };
    addKnown(CSIDL_DESKTOPDIRECTORY);
    addKnown(CSIDL_PERSONAL);
    addKnown(CSIDL_INTERNET_CACHE);
    addKnown(CSIDL_LOCAL_APPDATA);
    BeginScan(roots, L"HVantivirus — Quick Scan");
}

static void StartFullScan() {
    std::vector<fs::path> roots;
    DWORD mask = GetLogicalDrives();
    for (int i=0;i<26;i++) if (mask & (1u<<i)) {
        wchar_t root[4] = { (wchar_t)(L'A'+i),L':',L'\\',0 };
        UINT t = GetDriveTypeW(root);
        if (t == DRIVE_FIXED) roots.emplace_back(root);
    }
    BeginScan(roots, L"HVantivirus — Full Disk Scan");
}

static void StartCustomScan() {
    BROWSEINFOW b{}; b.hwndOwner=g_main; b.lpszTitle=L"Select a folder to scan"; b.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE id=SHBrowseForFolderW(&b); if(!id) return;
    wchar_t p[MAX_PATH]{}; if(SHGetPathFromIDListW(id,p)) BeginScan({fs::path(p)}, L"HVantivirus — Custom Scan");
    CoTaskMemFree(id);
}

static void StartFileScan() {
    if (g_scanning) return;
    wchar_t file[MAX_PATH]{};
    OPENFILENAMEW ofn{sizeof(ofn)};
    ofn.hwndOwner = g_main;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All files (*.*)\0*.*\0Programs (*.exe;*.dll;*.scr;*.msi)\0*.exe;*.dll;*.scr;*.msi\0Scripts (*.bat;*.cmd;*.ps1;*.vbs;*.js)\0*.bat;*.cmd;*.ps1;*.vbs;*.js\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    BeginScan({fs::path(file)}, L"HVantivirus — File Scan", true);
}

static void StartDroppedFiles(HDROP drop) {
    if (g_scanning) { DragFinish(drop); return; }
    UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
    std::vector<fs::path> roots;
    for (UINT i = 0; i < count; ++i) {
        wchar_t path[32768]{};
        if (DragQueryFileW(drop, i, path, static_cast<UINT>(sizeof(path) / sizeof(path[0])))) roots.emplace_back(path);
    }
    DragFinish(drop);
    if (!roots.empty()) BeginScan(roots, L"HVantivirus — Dropped File Scan", true);
}

static void StartProcessScan() {
    if (g_scanning) return;
    ResetStats(); g_cancelScan=false; g_scanning=true; EnableWindow(g_cancelBtn,TRUE); EnableWindow(g_quarantineBtn,FALSE);
    SetWindowTextW(g_status,L"HVantivirus — Process Scan"); SetWindowTextW(g_progressText,L"Inspecting running process executables...");
    g_scanThread = std::thread([](){
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); std::vector<fs::path> files;
        if(snap!=INVALID_HANDLE_VALUE){PROCESSENTRY32W e{sizeof(e)};if(Process32FirstW(snap,&e)){do{
            HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID);if(h){wchar_t p[32768];DWORD n=32768;if(QueryFullProcessImageNameW(h,0,p,&n))files.emplace_back(p);CloseHandle(h);} 
        }while(Process32NextW(snap,&e));}CloseHandle(snap);} 
        WorkerScan(files,true); PostMessageW(g_main,WM_SCAN_FINISHED,0,0);
    });
}

static void UpdateStatsUI() {
    wchar_t b[128];
    swprintf_s(b,L"%llu",g_stats.files.load()); SetWindowTextW(g_filesText,b);
    swprintf_s(b,L"%llu",g_stats.threats.load()+g_stats.suspicious.load()); SetWindowTextW(g_threatsText,b);
    std::wstring q = g_guardRunning ? L"Guard: ON" : L"Guard: OFF";
    SetWindowTextW(g_guardText,q.c_str());
}

static void PopulateResults() {
    ListView_DeleteAllItems(g_results);
    std::lock_guard<std::mutex> lk(g_dataMutex);
    int row=0;
    for (const auto& d : g_detections) {
        LVITEMW item{}; item.mask=LVIF_TEXT; item.iItem=row; std::wstring sev = d.score>=7?L"THREAT":L"SUSPICIOUS"; item.pszText=(LPWSTR)sev.c_str(); ListView_InsertItem(g_results,&item);
        ListView_SetItemText(g_results,row,1,(LPWSTR)d.reason.c_str()); ListView_SetItemText(g_results,row,2,(LPWSTR)d.path.c_str()); std::wstring sc=std::to_wstring(d.score); ListView_SetItemText(g_results,row,3,(LPWSTR)sc.c_str()); ListView_SetItemText(g_results,row,4,(LPWSTR)(d.sha256.empty()?L"unavailable":d.sha256).c_str()); ++row;
    }
}

static std::wstring NewQuarantineName() {
    SYSTEMTIME st{}; GetLocalTime(&st); wchar_t b[128]; swprintf_s(b,L"%04d%02d%02d_%02d%02d%02d_%u.hvq",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,GetCurrentProcessId()); return QuarantineDir()+L"\\"+b;
}

static void QuarantineAll() {
    std::vector<Detection> detections; { std::lock_guard<std::mutex> lk(g_dataMutex); detections=g_detections; }
    int moved=0;
    EnsureDirectories();
    for (const auto& d : detections) {
        if (!d.quarantineable) continue;
        std::error_code ec;
        if (!fs::exists(d.path,ec)) continue;
        std::wstring q=NewQuarantineName();
        if (MoveFileExW(d.path.c_str(),q.c_str(),MOVEFILE_COPY_ALLOWED|MOVEFILE_WRITE_THROUGH)) {
            std::wofstream meta(q+L".meta"); meta << d.path << L"\n" << d.reason << L"\n" << d.score << L"\n"; ++moved;
        }
    }
    if (moved) MessageBoxW(g_main,(L"Quarantined "+std::to_wstring(moved)+L" item(s).\n\nOpen Quarantine to inspect them.").c_str(),APP_NAME,MB_OK|MB_ICONINFORMATION);
    else MessageBoxW(g_main,L"No detected item could be moved. Some files may be protected or already gone.",APP_NAME,MB_OK|MB_ICONINFORMATION);
}

static void OpenQuarantine() {
    EnsureDirectories(); ShellExecuteW(g_main,L"open",QuarantineDir().c_str(),nullptr,nullptr,SW_SHOWNORMAL);
}

static bool SetRunAtStartup(bool enable) {
    HKEY key=nullptr;
    if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE|KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS) return false;
    bool ok=false;
    if(enable){
        wchar_t exe[32768]{}; DWORD n=GetModuleFileNameW(nullptr,exe,32768);
        if(n && n<32768){ std::wstring cmd=L"\""+std::wstring(exe,n)+L"\"";
            ok=RegSetValueExW(key,APP_NAME,0,REG_SZ,reinterpret_cast<const BYTE*>(cmd.c_str()),static_cast<DWORD>((cmd.size()+1)*sizeof(wchar_t)))==ERROR_SUCCESS; }
    } else { LONG r=RegDeleteValueW(key,APP_NAME); ok=(r==ERROR_SUCCESS||r==ERROR_FILE_NOT_FOUND); }
    RegCloseKey(key); return ok;
}
static bool IsRunAtStartup() {
    HKEY key=nullptr; if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS)return false;
    DWORD type=0,size=0; bool found=RegQueryValueExW(key,APP_NAME,nullptr,&type,nullptr,&size)==ERROR_SUCCESS && type==REG_SZ; RegCloseKey(key); return found;
}
static void RestoreQuarantineItem() {
    EnsureDirectories(); wchar_t file[32768]{};
    OPENFILENAMEW ofn{sizeof(ofn)}; ofn.hwndOwner=g_main; ofn.lpstrFile=file; ofn.nMaxFile=32768;
    ofn.lpstrFilter=L"HVantivirus quarantine (*.hvq)\0*.hvq\0All files (*.*)\0*.*\0"; ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(!GetOpenFileNameW(&ofn))return;
    std::wstring q=file, meta=q+L".meta", original, reason; int score=0;
    std::wifstream in(meta); if(!in||!std::getline(in,original)||original.empty()) {MessageBoxW(g_main,L"Quarantine metadata is missing or invalid. Restore cancelled.",APP_NAME,MB_OK|MB_ICONWARNING);return;}
    std::getline(in,reason); in>>score;
    std::wstring msg=L"Restore this quarantined file to its original location?\n\nOriginal: "+original+L"\nReason: "+reason+L"\n\nOnly restore it if you trust the file.";
    if(MessageBoxW(g_main,msg.c_str(),APP_NAME,MB_YESNO|MB_DEFBUTTON2|MB_ICONWARNING)!=IDYES)return;
    if(GetFileAttributesW(original.c_str())!=INVALID_FILE_ATTRIBUTES){MessageBoxW(g_main,L"A file already exists at the original path. Rename or move it first; no file was overwritten.",APP_NAME,MB_OK|MB_ICONWARNING);return;}
    if(!MoveFileExW(q.c_str(),original.c_str(),MOVEFILE_WRITE_THROUGH)){MessageBoxW(g_main,L"Restore failed. Check permissions and available disk space.",APP_NAME,MB_OK|MB_ICONERROR);return;}
    DeleteFileW(meta.c_str()); MessageBoxW(g_main,L"File restored. Scan it again before opening.",APP_NAME,MB_OK|MB_ICONINFORMATION);
}

static void SaveReport() {
    wchar_t file[MAX_PATH]=L"HVantivirus-report.txt";
    OPENFILENAMEW ofn{sizeof(ofn)}; ofn.hwndOwner=g_main;ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;ofn.lpstrFilter=L"Text report (*.txt)\0*.txt\0All files (*.*)\0*.*\0";ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
    if(!GetSaveFileNameW(&ofn)) return;
    std::wofstream out(file); if(!out){MessageBoxW(g_main,L"Could not save the report.",APP_NAME,MB_OK|MB_ICONERROR);return;}
    out<<APP_NAME<<L" security scan report\nGenerated: "<<NowString()<<L"\n\n";
    out<<L"Files checked: "<<g_stats.files.load()<<L"\nThreats: "<<g_stats.threats.load()<<L"\nSuspicious: "<<g_stats.suspicious.load()<<L"\nErrors: "<<g_stats.errors.load()<<L"\n\n";
    std::lock_guard<std::mutex> lk(g_dataMutex); for(auto& d:g_detections) out<<(d.score>=7?L"THREAT":"SUSPICIOUS")<<L" | "<<d.score<<L" | "<<d.reason<<L" | "<<d.path<<L"\n";
}

static std::vector<fs::path> GuardRoots() {
    wchar_t p[MAX_PATH]{}; std::vector<fs::path> roots;
    if(SUCCEEDED(SHGetFolderPathW(nullptr,CSIDL_DESKTOPDIRECTORY,nullptr,SHGFP_TYPE_CURRENT,p)))roots.emplace_back(p);
    if(SUCCEEDED(SHGetFolderPathW(nullptr,CSIDL_PERSONAL,nullptr,SHGFP_TYPE_CURRENT,p)))roots.emplace_back(std::wstring(p)+L"\\Downloads");
    return roots;
}

static FILETIME GetWriteTime(const fs::path& p, bool& ok) {
    WIN32_FILE_ATTRIBUTE_DATA d{}; ok=GetFileAttributesExW(p.c_str(),GetFileExInfoStandard,&d)!=FALSE; return d.ftLastWriteTime;
}

static bool SameFT(const FILETIME&a,const FILETIME&b){return a.dwLowDateTime==b.dwLowDateTime&&a.dwHighDateTime==b.dwHighDateTime;}

static void GuardLoop() {
    auto roots=GuardRoots();
    while(g_guardRunning){
        for(const auto& root:roots){
            std::error_code ec; if(!fs::exists(root,ec))continue;
            fs::recursive_directory_iterator it(root,fs::directory_options::skip_permission_denied,ec),end;
            for(;it!=end&&g_guardRunning;it.increment(ec)){
                if(ec){ec.clear();continue;} std::error_code te; if(!it->is_regular_file(te)||te)continue;
                fs::path p=it->path(); bool ok=false; FILETIME ft=GetWriteTime(p,ok); if(!ok)continue; std::wstring wp=p.wstring();
                auto old=g_guardSnapshot.find(wp); if(old==g_guardSnapshot.end()){g_guardSnapshot[wp]=ft; auto d=AnalyzeFile(p); if(d){PushDetection(*d); if(d->score>=7)++g_stats.threats;else ++g_stats.suspicious; PostMessageW(g_main,WM_GUARD_HIT,0,0);} }
                else if(!SameFT(old->second,ft)){old->second=ft;auto d=AnalyzeFile(p);if(d){PushDetection(*d);if(d->score>=7)++g_stats.threats;else ++g_stats.suspicious;PostMessageW(g_main,WM_GUARD_HIT,0,0);}}
            }
        }
        for(int i=0;i<30&&g_guardRunning;i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

static void ToggleGuard() {
    if(g_guardRunning){ g_guardRunning=false; if(g_guardThread.joinable())g_guardThread.join(); SetWindowTextW(g_guardBtn,L"Start Guard"); }
    else { g_guardRunning=true; g_guardSnapshot.clear(); SetWindowTextW(g_guardBtn,L"Stop Guard"); g_guardThread=std::thread(GuardLoop); }
    UpdateStatsUI();
}

static void SetControlFont(HWND h, HFONT f){SendMessageW(h,WM_SETFONT,(WPARAM)f,TRUE);}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch(m){
    case WM_CREATE:{
        INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_PROGRESS_CLASS|ICC_LISTVIEW_CLASSES|ICC_STANDARD_CLASSES}; InitCommonControlsEx(&ic);
        HFONT font=(HFONT)GetStockObject(DEFAULT_GUI_FONT); HFONT big=CreateFontW(28,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_OUTLINE_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
        CreateWindowW(L"STATIC",L"HVantivirus",WS_CHILD|WS_VISIBLE,28,20,300,40,h,0,g_inst,0); HWND title=GetWindow(h,GW_CHILD);SetControlFont(title,big);
        CreateWindowW(L"STATIC",L"Windows security scanner",WS_CHILD|WS_VISIBLE,31,58,300,22,h,0,g_inst,0);
        HWND st=CreateWindowW(L"STATIC",L"PROTECTION ACTIVE",WS_CHILD|WS_VISIBLE|SS_CENTER,760,25,180,32,h,0,g_inst,0);SetControlFont(st,font);
        g_status=CreateWindowW(L"STATIC",L"Ready",WS_CHILD|WS_VISIBLE,30,95,800,26,h,0,g_inst,0);SetControlFont(g_status,font);

        // Action buttons
        g_quickBtn=CreateWindowW(L"BUTTON",L"Quick Scan",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,30,135,150,42,h,(HMENU)101,g_inst,0);
        g_fullBtn=CreateWindowW(L"BUTTON",L"Full Scan",WS_CHILD|WS_VISIBLE,190,135,150,42,h,(HMENU)102,g_inst,0);
        g_customBtn=CreateWindowW(L"BUTTON",L"Custom Scan",WS_CHILD|WS_VISIBLE,350,135,150,42,h,(HMENU)103,g_inst,0);
        g_processBtn=CreateWindowW(L"BUTTON",L"Process Scan",WS_CHILD|WS_VISIBLE,510,135,150,42,h,(HMENU)104,g_inst,0);
        g_guardBtn=CreateWindowW(L"BUTTON",L"Start Guard",WS_CHILD|WS_VISIBLE,670,135,150,42,h,(HMENU)105,g_inst,0);
        g_fileBtn=CreateWindowW(L"BUTTON",L"Scan File...",WS_CHILD|WS_VISIBLE,30,180,150,38,h,(HMENU)111,g_inst,0);
        g_dropHint=CreateWindowW(L"STATIC",L"Tip: you can also drag one or more files here to scan them.",WS_CHILD|WS_VISIBLE,190,188,620,22,h,0,g_inst,0);
        for(HWND c=GetWindow(h,GW_CHILD);c;c=GetWindow(c,GW_HWNDNEXT))SetControlFont(c,font);

        CreateWindowW(L"STATIC",L"Scan progress",WS_CHILD|WS_VISIBLE,30,230,120,22,h,0,g_inst,0);
        g_progress=CreateWindowW(PROGRESS_CLASSW,L"",WS_CHILD|WS_VISIBLE,30,255,790,22,h,(HMENU)201,g_inst,0);SendMessageW(g_progress,PBM_SETRANGE,0,MAKELPARAM(0,100));
        g_progressText=CreateWindowW(L"STATIC",L"Idle",WS_CHILD|WS_VISIBLE,30,283,790,22,h,0,g_inst,0);

        HWND statsBox=CreateWindowW(L"BUTTON",L"Security status",WS_CHILD|WS_VISIBLE|BS_GROUPBOX,30,315,790,90,h,0,g_inst,0);SetControlFont(statsBox,font);
        CreateWindowW(L"STATIC",L"Files scanned",WS_CHILD|WS_VISIBLE,50,347,100,20,h,0,g_inst,0);g_filesText=CreateWindowW(L"STATIC",L"0",WS_CHILD|WS_VISIBLE,145,347,90,20,h,0,g_inst,0);
        CreateWindowW(L"STATIC",L"Detections",WS_CHILD|WS_VISIBLE,260,347,90,20,h,0,g_inst,0);g_threatsText=CreateWindowW(L"STATIC",L"0",WS_CHILD|WS_VISIBLE,345,347,90,20,h,0,g_inst,0);
        CreateWindowW(L"STATIC",L"Guard",WS_CHILD|WS_VISIBLE,460,347,70,20,h,0,g_inst,0);g_guardText=CreateWindowW(L"STATIC",L"OFF",WS_CHILD|WS_VISIBLE,520,347,120,20,h,0,g_inst,0);
        CreateWindowW(L"STATIC",L"Last scan",WS_CHILD|WS_VISIBLE,650,347,70,20,h,0,g_inst,0);g_lastScanText=CreateWindowW(L"STATIC",L"Never",WS_CHILD|WS_VISIBLE,710,347,95,20,h,0,g_inst,0);

        CreateWindowW(L"STATIC",L"Detections",WS_CHILD|WS_VISIBLE,30,420,150,24,h,0,g_inst,0);
        g_results=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|WS_BORDER|LVS_REPORT|LVS_SINGLESEL,30,448,790,165,h,(HMENU)301,g_inst,0);
        const wchar_t* cols[]={L"Severity",L"Reason",L"File",L"Score",L"SHA-256"};int widths[]={100,230,340,55,255};for(int i=0;i<5;i++){LVCOLUMNW c{LVCF_TEXT|LVCF_WIDTH};c.cx=widths[i];c.pszText=(LPWSTR)cols[i];ListView_InsertColumn(g_results,i,&c);}
        ListView_SetExtendedListViewStyle(g_results,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        g_cancelBtn=CreateWindowW(L"BUTTON",L"Cancel scan",WS_CHILD|WS_VISIBLE|WS_DISABLED,30,623,130,34,h,(HMENU)106,g_inst,0);
        g_quarantineBtn=CreateWindowW(L"BUTTON",L"Quarantine detections",WS_CHILD|WS_VISIBLE|WS_DISABLED,170,623,180,34,h,(HMENU)107,g_inst,0);
        CreateWindowW(L"BUTTON",L"Open Quarantine",WS_CHILD|WS_VISIBLE,360,623,150,34,h,(HMENU)108,g_inst,0);
        CreateWindowW(L"BUTTON",L"Save Report",WS_CHILD|WS_VISIBLE,520,623,130,34,h,(HMENU)109,g_inst,0);
        CreateWindowW(L"BUTTON",L"Clear",WS_CHILD|WS_VISIBLE,660,623,100,34,h,(HMENU)110,g_inst,0);
        CreateWindowW(L"BUTTON",L"Restore quarantined file...",WS_CHILD|WS_VISIBLE,30,665,210,32,h,(HMENU)112,g_inst,0);
        HWND startup=CreateWindowW(L"BUTTON",L"Start HVantivirus with Windows",WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,270,670,270,24,h,(HMENU)113,g_inst,0); SendMessageW(startup,BM_SETCHECK,IsRunAtStartup()?BST_CHECKED:BST_UNCHECKED,0);
        UpdateStatsUI(); return 0; }
    case WM_DROPFILES: StartDroppedFiles(reinterpret_cast<HDROP>(w)); return 0;
    case WM_COMMAND:
        switch(LOWORD(w)){
        case 101:StartQuickScan();return 0; case 102:StartFullScan();return 0; case 103:StartCustomScan();return 0; case 104:StartProcessScan();return 0; case 105:ToggleGuard();return 0;
        case 111:StartFileScan();return 0; case 106:g_cancelScan=true;SetWindowTextW(g_progressText,L"Cancel requested...");return 0;
        case 107:QuarantineAll();return 0; case 108:OpenQuarantine();return 0; case 109:SaveReport();return 0;
        case 112:RestoreQuarantineItem();return 0; case 113:{bool enable=SendMessageW((HWND)l,BM_GETCHECK,0,0)==BST_CHECKED;if(!SetRunAtStartup(enable)){MessageBoxW(h,L"Could not update Windows startup setting.",APP_NAME,MB_OK|MB_ICONERROR);SendMessageW((HWND)l,BM_SETCHECK,enable?BST_UNCHECKED:BST_CHECKED,0);}return 0;}
        case 110:if(!g_scanning){std::lock_guard<std::mutex>lk(g_dataMutex);g_detections.clear();ListView_DeleteAllItems(g_results);g_stats.files=0;g_stats.suspicious=0;g_stats.threats=0;g_stats.errors=0;UpdateStatsUI();SetWindowTextW(g_progressText,L"Idle");}return 0; }
        break;
    case WM_SCAN_PROGRESS:{ if(w==1){SetWindowTextW(g_progressText,L"Scanning files...");return 0;} auto*p=(unsigned long long*)l;if(p){unsigned long long done=p[0],total=p[1];int pct=total?(int)((done*100)/total):0;SendMessageW(g_progress,PBM_SETPOS,pct,0);wchar_t b[100];swprintf_s(b,L"Scanning: %llu / %llu files",done,total);SetWindowTextW(g_progressText,b);delete[]p;}UpdateStatsUI();return 0; }
    case WM_GUARD_HIT:{
        PopulateResults(); UpdateStatsUI();
        SetWindowTextW(g_status,L"HVantivirus — A suspicious file change was detected");
        Detection latest{}; bool have=false;
        { std::lock_guard<std::mutex> lk(g_dataMutex); if(!g_detections.empty()){latest=g_detections.back();have=true;} }
        if(have){
            std::wstring message=L"HVantivirus found a potentially suspicious file.\n\nFile: "+latest.path+L"\nReason: "+latest.reason+
                L"\nRisk score: "+std::to_wstring(latest.score)+L"/100\n\nThe file was NOT deleted or quarantined. Review it in the detections list.";
            MessageBoxW(h,message.c_str(),APP_NAME,MB_OK|MB_ICONWARNING|MB_TOPMOST);
        }
        return 0; }
    case WM_SCAN_FINISHED:{ if(g_scanThread.joinable())g_scanThread.join();g_scanning=false;EnableWindow(g_cancelBtn,FALSE);PopulateResults();UpdateStatsUI();SetWindowTextW(g_quarantineBtn,(g_detections.empty()?L"Quarantine detections":L"Quarantine detections"));EnableWindow(g_quarantineBtn,g_detections.empty()?FALSE:TRUE);g_lastScan=NowString();SetWindowTextW(g_lastScanText,g_lastScan.c_str());SendMessageW(g_progress,PBM_SETPOS,100,0);if(g_cancelScan)SetWindowTextW(g_progressText,L"Scan cancelled");else SetWindowTextW(g_progressText,L"Scan completed");if (!g_singleScanPath.empty() && g_stats.files.load() == 1 && g_detections.empty()) {
            std::wstring msg = L"No detection reported for selected file.\n\nSHA-256: " + (g_singleScanHash.empty()?L"unavailable":g_singleScanHash);
            SetWindowTextW(g_status,L"HVantivirus — File is clean according to current definitions/heuristics");
            MessageBoxW(h, msg.c_str(), APP_NAME, MB_OK | MB_ICONINFORMATION);
        } else {
            SetWindowTextW(g_status,L"HVantivirus — Scan finished");
        } return 0; }
    case WM_CLOSE: if(g_scanning){g_cancelScan=true;MessageBoxW(h,L"A scan is still running. Stop it first or wait for it to finish.",APP_NAME,MB_OK|MB_ICONINFORMATION);return 0;} DestroyWindow(h); return 0;
    case WM_DESTROY: g_guardRunning=false; if(g_guardThread.joinable())g_guardThread.join(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h,m,w,l);
}

int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR,int show){
    g_inst=inst;EnsureDirectories(); LoadHashDefinitions();
    INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_WIN95_CLASSES|ICC_PROGRESS_CLASS|ICC_LISTVIEW_CLASSES};InitCommonControlsEx(&ic);
    WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=inst;wc.lpszClassName=L"HVantivirusMain";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.hIcon=LoadIconW(nullptr,IDI_SHIELD);RegisterClassW(&wc);
    g_main=CreateWindowW(wc.lpszClassName, L"HVantivirus — Windows Antivirus", WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, CW_USEDEFAULT,CW_USEDEFAULT,870,735,nullptr,nullptr,inst,nullptr);
    if(!g_main)return 1; DragAcceptFiles(g_main, TRUE); ShowWindow(g_main,show);UpdateWindow(g_main); PostMessageW(g_main,WM_COMMAND,MAKEWPARAM(105,0),0);
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}if(g_scanThread.joinable())g_scanThread.join();if(g_guardThread.joinable())g_guardThread.join();return (int)msg.wParam;
}
