"""Yönetici girişi: argon2id parola + ZORUNLU TOTP ikinci faktör.

TOTP sırrı DB'de AES-GCM ile şifreli durur (anahtar DB dışında). İlk girişte yönetici kendi
sırrını kaydeder; sırrı öneren/onaylayan diğer yöneticiler hiç görmez.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..audit import chain, checkpoint
from ..context import Context
from ..crypto import rowmac
from ..db.connection import IntegrityError, transaction, update_row
from ..timekeeping import get_clock
from . import totp

MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60
_ph = PasswordHasher()
_DUMMY = _ph.hash("dummy-password-for-constant-time")

_lock = threading.Lock()
_failures: dict[str, list[float]] = {}
_last_totp_counter: dict[str, int] = {}


class AdminAuthError(RuntimeError):
    pass


def _locked(username: str) -> bool:
    with _lock:
        # Monotonik sayaç: sistem saatini ileri almak kilidi erken açmaz.
        recent = [t for t in _failures.get(username, []) if t > time.monotonic() - LOCK_SECONDS]
        _failures[username] = recent
        return len(recent) >= MAX_FAILURES


def _fail(username: str) -> None:
    with _lock:
        _failures.setdefault(username, []).append(time.monotonic())


def check_password(ctx: Context, username: str, password: str) -> dict[str, Any] | None:
    if _locked(username):
        raise AdminAuthError("too many failed attempts; try again later")
    row = ctx.conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    try:
        _ph.verify(row["pw_hash"] if row else _DUMMY, password)
        ok = row is not None
    except VerificationError:
        ok = False
    if not ok:
        _fail(username)
        return None
    row = dict(row)
    if not rowmac.verify(ctx.keys.row_mac, "admins", row):
        raise IntegrityError("admin row MAC invalid")
    return row


def _aad(admin_id: str) -> bytes:
    return f"totp:{admin_id}".encode()


def encrypt_secret(ctx: Context, admin_id: str, secret: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(ctx.keys.wrap).encrypt(nonce, secret.encode(), _aad(admin_id))


def decrypt_secret(ctx: Context, admin_id: str, blob: bytes) -> str:
    return AESGCM(ctx.keys.wrap).decrypt(blob[:12], blob[12:], _aad(admin_id)).decode()


def check_totp(ctx: Context, admin: dict[str, Any], code: str) -> bool:
    if _locked(admin["username"]):
        raise AdminAuthError("too many failed attempts; try again later")
    if admin["totp_secret_enc"] is None:
        return False
    counter = totp.match_counter(decrypt_secret(ctx, admin["id"], admin["totp_secret_enc"]), code,
                                 at=get_clock().now())
    with _lock:
        # Aynı kod (aynı zaman penceresi) ikinci kez kullanılamaz.
        if counter is None or counter <= _last_totp_counter.get(admin["id"], -1):
            ok = False
        else:
            _last_totp_counter[admin["id"]] = counter
            ok = True
    if not ok:
        _fail(admin["username"])
    return ok


def enroll_totp(ctx: Context, admin_id: str, secret: str, code: str) -> bool:
    if totp.match_counter(secret, code, at=get_clock().now()) is None:
        return False
    with transaction(ctx.conn):
        row = ctx.conn.execute("SELECT totp_secret_enc FROM admins WHERE id = ?",
                               (admin_id,)).fetchone()
        if row is None or row["totp_secret_enc"] is not None:
            raise AdminAuthError("TOTP already enrolled")
        chain.record(ctx.conn, ctx.keys, admin_id, "admin_totp_enrolled",
                     {"admin_id": admin_id})
        update_row(ctx.conn, ctx.keys.row_mac, "admins", {"id": admin_id},
                   {"totp_secret_enc": encrypt_secret(ctx, admin_id, secret)})
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
    return True
