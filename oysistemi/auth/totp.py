"""TOTP (RFC 6238 / RFC 4226) — harici bağımlılık olmadan.

Standart kimlik doğrulayıcı uygulamalarla uyumludur (Google Authenticator, Aegis, 1Password…):
SHA-1, 6 hane, 30 saniye.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
STEP = 30


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** DIGITS).zfill(DIGITS)


def now_code(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // STEP))


def match_counter(secret_b32: str, code: str, at: float | None = None,
                  window: int = 1) -> int | None:
    """Kod geçerliyse eşleşen sayaç değerini döner (tekrar kullanım kontrolü için)."""
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None
    counter = int((at or time.time()) // STEP)
    for c in range(counter - window, counter + window + 1):
        if hmac.compare_digest(_hotp(secret_b32, c), code):
            return c
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "OySistemi") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}")


def qr_svg(uri: str) -> str:
    """Kimlik doğrulayıcı uygulamanın tarayacağı karekod (satır içi SVG).

    Sayfanın içine gömülür: TOTP sırrı ayrı bir resim adresinden geçmez (önbelleğe/loga
    düşmez) ve CSP gevşetilmez (SVG'de betik ya da style özniteliği yok). Koyu temada da
    taranabilsin diye zemin her zaman beyazdır.
    """
    import segno

    return segno.make(uri, error="m").svg_inline(
        scale=5, border=4, dark="#000000", light="#ffffff", title="İki adımlı doğrulama karekodu")


def group(secret_b32: str) -> str:
    """Elle girişte okunabilirlik için 4'erli gruplar: ABCD EFGH ..."""
    return " ".join(secret_b32[i:i + 4] for i in range(0, len(secret_b32), 4))
