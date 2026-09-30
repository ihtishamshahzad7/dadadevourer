import secrets

from fastapi import Request, Response

from .settings import settings

ACCESS_COOKIE = "dd_access"
CSRF_COOKIE = "dd_csrf"


def set_session(response: Response, token: str) -> None:
    secure = settings.environment.lower() == "production"
    max_age = settings.jwt_expire_minutes * 60
    response.set_cookie(ACCESS_COOKIE, token, httponly=True, secure=secure, samesite="lax", max_age=max_age, path="/")
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, secure=secure, samesite="lax", max_age=max_age, path="/")


def clear_session(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def require_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("X-CSRF-Token")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        from fastapi import HTTPException
        raise HTTPException(403, "CSRF validation failed")
