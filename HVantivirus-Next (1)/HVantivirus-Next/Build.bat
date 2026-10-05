@echo off
setlocal
cd /d "%~dp0"
where g++ >nul 2>nul
if errorlevel 1 (
  echo [ERROR] MinGW g++ was not found in PATH.
  echo Install a Windows MinGW-w64 toolchain and add its bin folder to PATH,
  echo or build the project using the included GitHub Actions workflow.
  pause
  exit /b 1
)
if not exist bin\Release mkdir bin\Release
echo Building HVantivirus...
g++ -std=c++17 -O2 -Wall -mwindows src\main.cpp -o bin\Release\HVantivirus.exe -lcomctl32 -lcomdlg32 -lshell32 -lole32 -ladvapi32 -lbcrypt
if errorlevel 1 (
  echo [ERROR] Build failed. See compiler messages above.
  pause
  exit /b 1
)
echo.
echo Build succeeded: %~dp0bin\Release\HVantivirus.exe
echo You can run the EXE without opening Code::Blocks.
pause
endlocal
