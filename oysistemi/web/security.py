"""Web güvenliği: imzalı oturum çerezleri, CSRF, güvenlik başlıkları, hız sınırlama."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import deque
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from ..timekeeping import get_clock

ADMIN_COOKIE = "oys_admin"
VOTER_COOKIE = "oys_voter"
ADMIN_TTL = 2 * 3600
VOTER_TTL = 30 * 60


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(key: bytes, purpose: str, data: dict[str, Any], ttl: int) -> str:
    body = _b64(json.dumps({**data, "exp": int(get_clock().now()) + ttl}).encode())
    mac = hmac.new(key, f"{purpose}.{body}".encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(mac)}"


def unsign(key: bytes, purpose: str, token: str | None) -> dict[str, Any] | None:
    if not token or token.count(".") != 1:
        return None
    body, mac = token.split(".")
    expected = hmac.new(key, f"{purpose}.{body}".encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _unb64(mac)):
            return None
        data = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if data.get("exp", 0) < get_clock().now():  # sistem saati değil: güvenilir saat
        return None
    return data


def new_csrf() -> str:
    return secrets.token_urlsafe(24)


def set_cookie(resp: Response, name: str, value: str, ttl: int, secure: bool) -> None:
    resp.set_cookie(name, value, max_age=ttl, httponly=True, secure=secure, samesite="strict",
                    path="/")


CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def _same_origin(request: Request) -> bool:
    """Durum değiştiren istek bu siteden mi geliyor?

    Önce Sec-Fetch-Site (tarayıcı koyar, sayfa değiştiremez), yoksa Origin'e bakılır.
    İkisi de yoksa (tarayıcı dışı istemci) izin verilir; CSRF belirteci ve SameSite=Strict
    çerezler ikinci savunma hattıdır.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    origin = request.headers.get("origin")
    return origin is None or origin == f"{request.url.scheme}://{request.url.netloc}"


class SecurityMiddleware(BaseHTTPMiddleware):
    """Güvenlik başlıkları + durum değiştiren isteklerde Origin kontrolü."""

    def __init__(self, app, hsts: bool) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS") and not _same_origin(request):
            return PlainTextResponse("cross-origin request refused", status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        # "no-referrer" DEĞİL: o politika form POST'larında Origin'i "null" yapar ve
        # aynı-köken kontrolünü bozar. "same-origin" dış sitelere yine hiçbir şey sızdırmaz.
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if self.hsts:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp


class RateLimiter:
    """Bellek içi kayan pencere. Küçük kurulum (tek süreç) için yeterli."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True
