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

> Only scan systems you own or have explicit permission to test.
