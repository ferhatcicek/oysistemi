"""FastAPI uygulaması.

Her istek kendi SQLite bağlantısını açar ve şema parmak izini kontrol eder: biri çalışan
sistemde bir tetikleyiciyi silerse bir sonraki istekten itibaren uygulama kilitlenir.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..config import Settings
from ..context import Context, LockedError, check_clock_against_db, configure_clock
from ..db import connection
from ..db.connection import IntegrityError
from ..timekeeping import TrustedClock, get_clock, parse_iso, set_clock
from .security import RateLimiter, SecurityMiddleware

HERE = Path(__file__).parent
log = logging.getLogger("oysistemi")
templates = Jinja2Templates(directory=HERE / "templates")


class Redirect(Exception):
    def __init__(self, url: str) -> None:
        self.url = url


def get_ctx(request: Request) -> Iterator[Context]:
    state = request.app.state
    conn = connection.connect(state.settings.db_path)
    try:
        if connection.schema_fingerprint(conn) != connection.expected_schema_fingerprint():
            raise LockedError("schema mismatch")
        yield Context(conn=conn, keys=state.keys, settings=state.settings)
    finally:
        conn.close()


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def _scheduler(settings: Settings, stop: threading.Event) -> None:
    """Arka plan: saat sıçraması denetimi, düzenli NTP eşitleme, zamanı gelen kapanışlar."""
    from ..context import open_context
    from ..elections.service import close_due_elections

    ticks = 0
    while not stop.wait(15):
        clock = get_clock()
        clock.check_jump()
        ticks += 1
        if ticks % 40 == 0:  # ~10 dakikada bir
            clock.sync()
        try:
            ctx = open_context(settings)
        except Exception:  # ör. şema kilidi: zamanlayıcı ölmemeli, ama sessiz de kalmamalı
            log.exception("scheduler: cannot open database")
            continue
        try:
            for eid in close_due_elections(ctx):
                log.warning("scheduler: election %s closed and tallied", eid)
        except Exception:
            log.exception("scheduler: automatic close failed")
        finally:
            ctx.close()


def localtime(ts: str | None, tz: str = "Europe/Istanbul") -> str:
    if not ts:
        return "—"
    return parse_iso(ts).astimezone(ZoneInfo(tz)).strftime("%d.%m.%Y %H:%M")


def create_app(settings: Settings | None = None, *, clock: TrustedClock | None = None,
               scheduler: bool = False) -> FastAPI:
    settings = settings or Settings.from_env()
    from ..osprotect import restrict_umask
    restrict_umask()
    if clock is None:
        configure_clock(settings)
    else:
        set_clock(clock)
    check_clock_against_db(settings)
    templates.env.filters["localtime"] = lambda ts: localtime(ts, settings.timezone)
    templates.env.globals["clock"] = get_clock
    templates.env.globals["tzname"] = settings.timezone
    templates.env.globals["source_url"] = settings.source_url
    from .. import __version__
    templates.env.globals["version"] = __version__
    templates.env.filters["localinput"] = lambda ts: to_local_input(ts, settings.timezone)
    app = FastAPI(title="OySistemi", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.keys = settings.load_keys()
    app.state.limiter = RateLimiter()

    # Açılışta bütünlük: şema farklıysa hiç başlama.
    conn = connection.connect(settings.db_path)
    try:
        if connection.schema_fingerprint(conn) != connection.expected_schema_fingerprint():
            raise LockedError("database schema does not match; run `oysistemi verify`")
    finally:
        conn.close()

    app.add_middleware(SecurityMiddleware, hsts=settings.cookie_secure)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    from . import routes_admin, routes_public
    app.include_router(routes_public.router)
    app.include_router(routes_admin.router)

    if scheduler:
        stop = threading.Event()
        threading.Thread(target=_scheduler, args=(settings, stop), daemon=True,
                         name="oys-scheduler").start()
        app.state.scheduler_stop = stop

    @app.exception_handler(Redirect)
    async def _redirect(_: Request, exc: Redirect):
        return RedirectResponse(exc.url, status_code=303)

    @app.exception_handler(LockedError)
    async def _locked(request: Request, _: LockedError):
        return render(request, "error.html", 503, title="Sistem kilitlendi",
                      message="Veritabanı şeması beklenenden farklı. Olası müdahale nedeniyle "
                              "sistem güvenli moda geçti. Yöneticiler `oysistemi verify` "
                              "komutunu çalıştırmalıdır.")

    @app.exception_handler(IntegrityError)
    async def _integrity(request: Request, exc: IntegrityError):
        return render(request, "error.html", 500, title="Bütünlük alarmı",
                      message=f"Kurcalanmış veri tespit edildi; işlem durduruldu. ({exc})")

    @app.exception_handler(LookupError)
    async def _notfound(request: Request, _: LookupError):
        return render(request, "error.html", 404, title="Bulunamadı",
                      message="Aradığınız kayıt bulunamadı.")

    return app


def app_factory() -> FastAPI:
    """uvicorn --factory oysistemi.web.app:app_factory"""
    return create_app(scheduler=True)


def to_utc_iso(local_value: str, tz: str) -> str | None:
    """<input type=datetime-local> değeri (yerel saat) → UTC ISO."""
    if not local_value:
        return None
    dt = datetime.fromisoformat(local_value).replace(tzinfo=ZoneInfo(tz))
    return dt.astimezone(ZoneInfo("UTC")).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_local_input(ts: str | None, tz: str) -> str:
    if not ts:
        return ""
    return parse_iso(ts).astimezone(ZoneInfo(tz)).strftime("%Y-%m-%dT%H:%M")
