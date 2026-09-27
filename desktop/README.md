# DadaDevourer Desktop

DadaDevourer is a Windows-first, local-first authorized security assessment application. It uses Tauri 2 + React, native SQLite persistence, and a bundled Python scanner sidecar.

## Workflow

Project → Authorization/Scope → Target → Scan → Findings/Evidence → Report

Current desktop capabilities:

- Project and client assessment workspaces
- Authorized target inventory
- Scope confirmation and authorization expiry
- Local SQLite persistence
- Security-header assessment
- TLS/certificate assessment
- Passive technology/disclosure assessment
- Combined full assessment
- Scan lifecycle and timeout protection
- Finding severity/status management
- Evidence and recommendations
- Local assessment report generation
- Report history
- Local audit trail
- GitHub updater foundation
- Windows x64 NSIS packaging

Use only against systems you own or have explicit permission to assess. The scanner uses controlled HTTP(S)/TLS observations and does not provide credential stuffing, stealth/evasion, destructive exploitation, or mass public scanning.

## Development

Requirements:

- Windows x64 for native installer builds
- Node.js 22+
- Python 3.13+
- Rust stable
- Tauri 2 prerequisites

Run:

```powershell
cd desktop
npm install
npm run tauri:dev
```

## Windows installer

```powershell
cd desktop
.\scripts\build-windows.ps1
```

Installers are produced under:

```text
desktop/src-tauri/target/release/bundle/nsis/
```

Generated installers and scanner binaries should not be committed to source control.

## Install/update latest GitHub release

From Windows CMD:

```cmd
cd desktop\scripts
install-latest.cmd
```

Update:

```cmd
cd desktop\scripts
update-latest.cmd
```

The scripts query only the latest GitHub release of this repository and select the Windows NSIS `.exe` installer asset. NSIS is the supported Windows installer format in the release pipeline. Application data is kept in the Tauri/SQLite application-data location and is not intentionally removed by an installer upgrade.

## Safe push workflow

```cmd
cd desktop\scripts
push-latest.cmd "feat: describe your change"
```

This runs the desktop frontend build first and refuses to push if that build fails.

Manual equivalent:

```cmd
git add .
git commit -m "feat: update DadaDevourer"
git push origin main
```

## Release and updater signing

GitHub Actions builds the Windows x64 scanner and Tauri installers and publishes a GitHub Release. Signed updater artifacts require these GitHub Actions secrets:

- TAURI_UPDATER_PUBLIC_KEY
- TAURI_SIGNING_PRIVATE_KEY
- TAURI_SIGNING_PRIVATE_KEY_PASSWORD

Never commit the private signing key. Until signing secrets are configured, the workflow can publish normal installers but the in-app updater cannot safely install unsigned updates.

## Architecture

```
DadaDevourer.exe
 ├─ Tauri + React UI
 ├─ Native SQLite
 └─ dadadevourer-scanner.exe
     └─ JSON Lines stdin/stdout
        ├─ security headers
        ├─ TLS
        └─ technology/disclosure
```
