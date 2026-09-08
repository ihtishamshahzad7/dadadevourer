from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .settings import settings
from .routers import auth, targets, headers, scans

app = FastAPI(title="DadaDevourer API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])
app.include_router(headers.router, prefix="/api/v1/scans/headers", tags=["headers"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])

@app.get("/health")
async def health():
    return {"status": "ok", "service": "dadadevourer-api", "version": "0.2.0"}
