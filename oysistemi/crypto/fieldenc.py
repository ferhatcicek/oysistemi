"""Hassas sütunların AES-256-GCM ile şifrelenmesi.

Şifrelenen alanlar:
  voters.display_name, voters.email   kişisel veri
  ballots.ballot                      oy içeriği (dosya çalınsa bile ara sonuç görülemez)
  audit_log.payload, voter_log.payload, change_requests.payload
                                      içlerinde ad/e-posta ve işlem ayrıntıları var

Her değer, ait olduğu satıra AAD ile bağlanır (ör. "ballots.ballot/<seçim>/<token_hash>").
Şifreli bir değer başka bir satıra kopyalanırsa çözülemez; yani DB'ye erişen biri oyları ya
da adları satırlar arasında yer değiştiremez.
"""
from __future__ import annotations

import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc1:"


class FieldDecryptError(Exception):
    """Şifre çözülemedi: yanlış anahtar, değiştirilmiş veri ya da başka satıra taşınmış değer."""


def encrypt(key: bytes, aad: str, plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), aad.encode())
    return PREFIX + base64.b64encode(nonce + ct).decode()


def decrypt(key: bytes, aad: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith(PREFIX):
        raise FieldDecryptError(f"{aad}: value is not encrypted (written outside the app?)")
    raw = base64.b64decode(value[len(PREFIX):])
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode()).decode()
    except (InvalidTag, ValueError):
        raise FieldDecryptError(f"{aad}: cannot decrypt (tampered or moved)") from None
