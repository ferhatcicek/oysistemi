"""Uygulama bağlamı: bağlantı + anahtarlar + ayarlar. Açılışta şema bütünlüğü denetlenir."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .config import Keys, Settings
from .db import connection
from .timekeeping import ClockError, TrustedClock, set_clock


class LockedError(RuntimeError):
    """Şema beklenenden farklı (tetikleyici silinmiş/değiştirilmiş olabilir)."""


@dataclass
class Context:
    conn: sqlite3.Connection
    keys: Keys
    settings: Settings

    def close(self) -> None:
        self.conn.close()


def initialise(settings: Settings, *, recovery_passphrase: str | None = None,
               passphrase: str | None = None, harden: bool = True) -> None:
    """Yeni kurulum: önce klasörler kilitlenir, sonra anahtar ve şema yazılır."""
    from . import osprotect
    osprotect.restrict_umask()
    for d in osprotect.protected_dirs(settings):
        d.mkdir(parents=True, exist_ok=True)
    if harden:
        failed = osprotect.harden_all(settings)
        if failed:
            raise PermissionError("could not restrict folder permissions: " + "; ".join(failed))
    settings.create_master_key(recovery_passphrase=recovery_passphrase, passphrase=passphrase)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connection.connect(settings.db_path)
    try:
        connection.init_schema(conn)
    finally:
        conn.close()


def open_context(settings: Settings, *, allow_locked: bool = False) -> Context:
    conn = connection.connect(settings.db_path)
    if not allow_locked and connection.schema_fingerprint(conn) != \
            connection.expected_schema_fingerprint():
        conn.close()
        raise LockedError("database schema does not match the expected schema; refusing to "
                          "start. Run `oysistemi verify` for details.")
    return Context(conn=conn, keys=settings.load_keys(), settings=settings)


def configure_clock(settings: Settings) -> TrustedClock:
    """Güvenilir saati kurar, dış kaynaklarla eşitler ve tüm sistemin saati yapar."""
    clock = TrustedClock(mode=settings.time_mode, sources=settings.time_sources,
                         quorum=settings.time_quorum, tolerance=settings.time_tolerance)
    clock.sync()
    set_clock(clock)
    return clock


def check_clock_against_db(settings: Settings) -> None:
    """Saat, denetim kaydının son zamanının gerisindeyse geri alma alarmı kurar."""
    from .audit.chain import check_high_water
    if not settings.db_path.exists():
        return
    conn = connection.connect(settings.db_path)
    try:
        check_high_water(conn)
    except ClockError:
        pass  # saat 'tampered' olarak işaretlendi; zamana bağlı işlemler duracak
    finally:
        conn.close()
