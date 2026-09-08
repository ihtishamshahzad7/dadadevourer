# DadaDevourer Desktop

The primary DadaDevourer client is a native Windows x64 application built with Tauri 2 and React/TypeScript.

## Development

From this directory:

```powershell
npm install
npm run tauri:dev
```

The desktop client currently provides the application shell and workspace UI. The next integration stage connects authentication, the local scanner service, persistent scan state, and the existing FastAPI scanner API.

## Windows installer

```powershell
npm install
npm run tauri:build
```

Tauri is configured to produce both an NSIS installer and an MSI package for Windows.

## Architecture

- `src/` — desktop UI
- `src-tauri/` — native Windows runtime and installer configuration
- `../backend/` — FastAPI API and security scanner services

The application is intended for systems the operator owns or has explicit authorization to assess.
