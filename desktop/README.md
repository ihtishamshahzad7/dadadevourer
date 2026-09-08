# DadaDevourer Desktop

DadaDevourer is a Windows-first authorized security testing application. The desktop shell is built with Tauri and React, while scanning runs in a bundled Python sidecar process.

## Architecture

```text
DadaDevourer.exe
  ├─ Tauri + React UI
  ├─ local application state
  └─ dadadevourer-scanner.exe
       └─ JSON Lines stdin/stdout protocol
            └─ Headers scanner
```

The scanner is intentionally restricted to HTTP(S) targets on ports 80/443 and rejects non-publicly-routable addresses. Use it only against systems you own or are explicitly authorized to test.

## Development

```powershell
cd desktop
npm install
npm run dev
```

For the full Tauri desktop shell, install the Rust/Tauri prerequisites and run:

```powershell
npm run tauri:dev
```

## Windows x64 installer

The repository includes `scripts/build-windows.ps1`. On a Windows build machine with Python 3, Node.js/npm, Rust/Cargo and the Tauri prerequisites installed:

```powershell
cd desktop
.\scripts\build-windows.ps1
```

The script builds the Python scanner with PyInstaller, places the target-specific sidecar under `src-tauri/binaries/`, builds the Tauri application, and produces NSIS/MSI installers under `src-tauri/target/release/bundle/`.

Do not commit the generated `.exe` sidecar to source control; CI/release builds should generate it as part of the build pipeline.
