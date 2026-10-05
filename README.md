# DadaDevourer

Production-grade foundation for an authorized web security testing platform.

## Stack

- Next.js + TypeScript frontend
- FastAPI + Python API
- PostgreSQL + SQLAlchemy + Alembic
- Redis asynchronous scan queue
- Dedicated Python worker
- Docker Compose
- GitHub Actions CI

## Current capabilities

1. JWT registration/login foundation.
2. Per-user target creation and listing.
3. Target ownership isolation.
4. Asynchronous security-header scans.
5. Persistent scan status and findings.
6. Scan history API.
7. Public HTTP(S) target validation; private, loopback, link-local and reserved destinations are rejected.

## Local development

Copy `.env.example` to `.env` and set strong secrets. Then run:

```bash
docker compose up --build
```

The API is available on port 8000 and the web application on port 3000.

The API container applies Alembic migrations before starting. The worker consumes queued scan jobs from Redis.

## Windows desktop updater

The Windows desktop application uses the Tauri updater to install signed releases in-app. Updates are delivered from:

```
https://github.com/ihtishamshahzad7/dadadevourer/releases/latest/download/latest.json
```

### One-time signing setup

Generate the updater keypair with the Tauri CLI:

```bash
npx tauri signer generate -w ~/.tauri/dadadevourer.key
```

The public key belongs in `desktop/src-tauri/tauri.conf.json` under `plugins.updater.pubkey`. The private key must never be committed to Git.

For GitHub Actions, add these repository secrets:

- `TAURI_PRIVATE_KEY` — complete contents of `~/.tauri/dadadevourer.key`
- `TAURI_KEY_PASSWORD` — the password chosen when generating the key. If the key was generated without a password, leave this secret empty.

The release workflow also accepts the modern Tauri names `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` for compatibility with current Tauri CLI releases.

Keep a secure offline backup of the private key. Losing the updater private key prevents already-installed clients that trust this public key from accepting future signed updates.

If the signing secrets are absent, the Windows release workflow still builds the normal NSIS and MSI installers, but it intentionally skips updater artifacts because Tauri requires signed updater bundles. This keeps ordinary installer releases from failing while leaving auto-update disabled until signing is configured.

> Only scan systems you own or have explicit permission to test.
