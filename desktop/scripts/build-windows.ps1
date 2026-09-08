$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Desktop = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$Engine = Join-Path $Desktop "engine"
$TauriBinaries = Join-Path $Desktop "src-tauri\binaries"
$Venv = Join-Path $Desktop ".venv-scanner"
$TargetTriple = "x86_64-pc-windows-msvc"

Write-Host "== DadaDevourer Windows x64 build ==" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3 is required to build the scanner sidecar."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is required to build the desktop frontend."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust/Cargo is required to build the Tauri application."
}

if (-not (Test-Path $Venv)) {
    python -m venv $Venv
}
$Python = Join-Path $Venv "Scripts\python.exe"
$Pip = Join-Path $Venv "Scripts\pip.exe"

& $Python -m pip install --upgrade pip
& $Pip install -r (Join-Path $Engine "requirements.txt")

if (Test-Path (Join-Path $Engine "build")) {
    Remove-Item -Recurse -Force (Join-Path $Engine "build")
}
if (Test-Path (Join-Path $Engine "dist")) {
    Remove-Item -Recurse -Force (Join-Path $Engine "dist")
}

Push-Location $Engine
try {
    & $Python -m PyInstaller --clean --noconfirm dadadevourer-scanner.spec
} finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $TauriBinaries | Out-Null
$BuiltSidecar = Join-Path $Engine "dist\dadadevourer-scanner.exe"
if (-not (Test-Path $BuiltSidecar)) {
    throw "PyInstaller did not produce $BuiltSidecar"
}

$Destination = Join-Path $TauriBinaries "dadadevourer-scanner-$TargetTriple.exe"
Copy-Item $BuiltSidecar $Destination -Force
Write-Host "Scanner sidecar: $Destination" -ForegroundColor Green

Push-Location $Desktop
try {
    npm install
    npm run build
    npm run tauri:build
} finally {
    Pop-Location
}

Write-Host "Build complete. Tauri installers are under desktop/src-tauri/target/release/bundle/" -ForegroundColor Green
