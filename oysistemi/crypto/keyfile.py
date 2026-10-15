"""Ana anahtar dosyası: koruma modları ve kurtarma anahtarı.

Modlar:
  dpapi       Windows varsayılanı. Anahtar, servisi çalıştıran Windows hesabına ve makineye
              bağlıdır; dosya kopyalansa bile başka yerde açılmaz. Parola istemez (servis dostu).
  passphrase  Anahtar scrypt + AES-256-GCM ile parolaya bağlı. Taşınabilir; kurtarma anahtarı
              ve şifreli yedekler bu modu kullanır. Açılışta parola gerekir (OYS_PASSPHRASE).
  file        Ham anahtar (yalnızca dosya izinleriyle korunur). Önerilmez; doğrulayıcı uyarır.

Alanlar şifreli olduğundan ANAHTAR KAYBI = VERİ KAYBI. Kurulumda mutlaka bir kurtarma
anahtarı (parola korumalı) üretilip çevrimdışı saklanmalıdır.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import dpapi

KEY_LEN = 32
MIN_PASSPHRASE = 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**16, 8, 1
PROTECTIONS = ("dpapi", "passphrase", "file")


class KeyFileError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _kdf(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def seal_with_passphrase(data: bytes, passphrase: str, purpose: str) -> dict:
    if len(passphrase) < MIN_PASSPHRASE:
        raise KeyFileError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = _kdf(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, data, purpose.encode())
    return {"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt),
            "nonce": _b64(nonce), "ct": _b64(ct)}


def open_with_passphrase(rec: dict, passphrase: str, purpose: str) -> bytes:
    key = _kdf(passphrase, _unb64(rec["salt"]), rec["n"], rec["r"], rec["p"])
    try:
        return AESGCM(key).decrypt(_unb64(rec["nonce"]), _unb64(rec["ct"]), purpose.encode())
    except InvalidTag:
        raise KeyFileError("wrong passphrase or corrupted file") from None


def encode(master: bytes, protection: str, passphrase: str | None = None) -> bytes:
    if len(master) != KEY_LEN:
        raise KeyFileError("master key must be 32 bytes")
    rec: dict = {"format": "oysistemi-key", "v": 1, "protection": protection}
    if protection == "dpapi":
        rec["blob"] = _b64(dpapi.protect(master))
    elif protection == "passphrase":
        if not passphrase:
            raise KeyFileError("passphrase required")
        rec.update(seal_with_passphrase(master, passphrase, "oysistemi/master-key"))
    elif protection == "file":
        rec["key"] = _b64(master)
    else:
        raise KeyFileError(f"unknown protection: {protection}")
    return json.dumps(rec, indent=1).encode()


def decode(raw: bytes, passphrase_cb: Callable[[], str] | None = None) -> tuple[bytes, str]:
    """Dönüş: (ana anahtar, koruma modu)."""
    if len(raw) == KEY_LEN and not raw.startswith(b"{"):
        return raw, "file"  # eski biçim
    try:
        rec = json.loads(raw)
    except ValueError:
        raise KeyFileError("unreadable key file") from None
    if rec.get("format") != "oysistemi-key":
        raise KeyFileError("not an OySistemi key file")
    prot = rec.get("protection")
    if prot == "dpapi":
        return dpapi.unprotect(_unb64(rec["blob"])), prot
    if prot == "passphrase":
        if passphrase_cb is None:
            raise KeyFileError("this key is passphrase-protected; set OYS_PASSPHRASE")
        return open_with_passphrase(rec, passphrase_cb(), "oysistemi/master-key"), prot
    if prot == "file":
        return _unb64(rec["key"]), prot
    raise KeyFileError(f"unknown protection: {prot}")


def write_new(path: Path, data: bytes) -> None:
    """Var olan dosyanın üzerine ASLA yazmaz (O_EXCL)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def replace(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".new")
    if tmp.exists():
        tmp.unlink()
    write_new(tmp, data)
    os.replace(tmp, path)
