@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "DESKTOP=%SCRIPT_DIR%.."
set "ENGINE=%DESKTOP%\engine"
set "BINARIES=%DESKTOP%\src-tauri\binaries"
set "TARGET_TRIPLE=x86_64-pc-windows-msvc"

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python 3.13+ is required to build the scanner sidecar.
  exit /b 1
)

if not exist "%ENGINE%\requirements.txt" (
  echo ERROR: Scanner requirements file was not found.
  exit /b 1
)

python -m pip install --upgrade pip
if errorlevel 1 exit /b 1
python -m pip install -r "%ENGINE%\requirements.txt"
if errorlevel 1 exit /b 1

if exist "%ENGINE%\build" rmdir /s /q "%ENGINE%\build"
if exist "%ENGINE%\dist" rmdir /s /q "%ENGINE%\dist"
if not exist "%BINARIES%" mkdir "%BINARIES%"

pushd "%ENGINE%"
python -m PyInstaller --clean --noconfirm dadadevourer-scanner.spec
if errorlevel 1 (
  popd
  exit /b 1
)
popd

if not exist "%ENGINE%\dist\dadadevourer-scanner.exe" (
  echo ERROR: PyInstaller did not produce the scanner executable.
  exit /b 1
)

copy /y "%ENGINE%\dist\dadadevourer-scanner.exe" "%BINARIES%\dadadevourer-scanner-%TARGET_TRIPLE%.exe" >nul
if errorlevel 1 exit /b 1

echo Scanner sidecar ready:
echo %BINARIES%\dadadevourer-scanner-%TARGET_TRIPLE%.exe
exit /b 0
