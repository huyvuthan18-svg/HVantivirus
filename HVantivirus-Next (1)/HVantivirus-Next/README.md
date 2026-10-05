# HVantivirus Pro

A practical Windows antivirus-style defensive prototype written in C++17 + Win32 API. It is designed to feel like a real desktop security utility while remaining transparent about its limits.

## Included
- Quick Scan of common user folders.
- Full Scan of fixed Windows drives.
- Custom Folder Scan.
- **Single File Scan** with a Windows file picker.
- **Drag-and-drop scanning** for one or multiple files.
- Running Process Scan.
- EICAR test-signature detection.
- Local SHA-256 signature database (`definitions.txt`) with the EICAR test hash preloaded.
- SHA-256 calculation for file scans and detected files.
- Heuristic detection for deceptive double extensions, suspicious script/command strings, high-entropy samples, and suspicious PE/script combinations.
- Scan progress, counters, detection table, hash column, and report export.
- Quarantine by moving detected files into `%LOCALAPPDATA%\HVantivirus\Quarantine` with metadata.
- User-folder Guard starts automatically when the app opens and watches Desktop/Downloads for new or modified files while the app is running. It can be stopped with the Guard button. A Windows warning dialog is shown for a detection; files are not automatically deleted or quarantined.
- Classic Win32 UI with no third-party runtime dependency.

## Custom signatures
`definitions.txt` ships next to the executable and can be edited with a text editor. Add one SHA-256 per line using:

```text
SHA256|Description
```

Lines beginning with `#` are comments. The program creates the file on first run if it does not exist.

## Important security note
This is a **defensive prototype**, not a replacement for Microsoft Defender or a commercial endpoint security product. Guard uses periodic folder polling, not a kernel file-system minifilter, so it is not guaranteed to see every file operation and may use CPU on large folders. The download monitor checks files after they appear in the watched folder; it cannot block a browser download before the user starts it. True pre-download blocking needs browser-specific integration and additional security review. The built-in definition set is intentionally small and the heuristic engine can miss malware or produce false positives. Do not use it as your only security layer. Do not claim guaranteed protection.

The EICAR test signature is a harmless antivirus test string intended for scanner testing.

## Build with Code::Blocks
1. Install Code::Blocks with a MinGW compiler that supports C++17.
2. Open `HVantivirus.cbp`.
3. Select `Release`.
4. Build with `Ctrl+F9`.
5. The executable is expected at `bin/Release/HVantivirus.exe`.

The project links against the Windows BCrypt library for SHA-256 hashing.


## HVantivirus Next additions
- Optional per-user Windows startup entry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), controlled by the checkbox in the app. This does not install a service or require administrator rights.
- Manual quarantine restore: select a `.hvq` file, review its recorded original path and reason, confirm explicitly; existing destination files are never overwritten. Only restore files you trust and scan them again before opening.
- Existing heuristic scanning remains advisory and can produce false positives.

## Security and implementation limits
This build does not yet implement a signed online signature updater, browser download interception, or system-wide kernel-level protection. Do not treat the app as a replacement for Microsoft Defender. A production signature updater needs a pinned public-key signature verification design and a trusted release channel; browser interception and system-wide protection require separately designed, signed and thoroughly tested Windows components. No Windows executable was built or tested in this environment.

## Build without opening Code::Blocks (Windows)

You can build the executable by double-clicking `Build.bat`, provided a compatible MinGW-w64 `g++` toolchain is installed and available in `PATH`. The executable is written to `bin/Release/HVantivirus.exe`. This script does not install a compiler and does not make a prebuilt executable.

Alternatively, after pushing the repository to GitHub, the included GitHub Actions workflow can build the Windows executable. Open the repository's **Actions** tab, select the latest successful **Build HVantivirus** run, and download the `HVantivirus-Windows` artifact.

The project has not been validated as a production antivirus. Keep Microsoft Defender enabled and test only in a disposable environment.
