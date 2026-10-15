"""Satır bütünlük kodları (row MAC).

Hassas tablolardaki her satır, DB dışında tutulan anahtarla HMAC'lenir. Veritabanına
doğrudan (uygulamayı atlayarak) eklenen ya da değiştirilen satırın MAC'i geçersiz olur.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

MAC_FIELDS: dict[str, tuple[str, ...]] = {
    "voters": ("id", "display_name", "email", "status", "created_at"),
    "admins": ("id", "username", "pw_hash", "totp_secret_enc", "role", "created_at"),
    "elections": ("id", "title", "ballot_type", "config", "config_hash", "status", "roll_hash",
                  "pubkey_pem", "privkey_wrapped", "result", "created_by"),
    "election_voters": ("election_id", "voter_id"),
    "change_requests": ("id", "kind", "payload", "proposed_by", "status",
                        "required_approvals", "created_at"),
    "auth_codes": ("election_id", "voter_id", "method", "code_hash", "expires_at", "attempts",
                   "used"),
}

PRIMARY_KEYS: dict[str, tuple[str, ...]] = {
    "voters": ("id",),
    "admins": ("id",),
    "elections": ("id",),
    "election_voters": ("election_id", "voter_id"),
    "change_requests": ("id",),
    "auth_codes": ("election_id", "voter_id", "method"),
}


def _canon(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"b": bytes(value).hex()}
    return value


def canonical_row(table: str, row: Mapping[str, Any]) -> bytes:
    fields = MAC_FIELDS[table]
    return json.dumps([table, [_canon(row[f]) for f in fields]],
                      separators=(",", ":"), ensure_ascii=False).encode()


def compute(key: bytes, table: str, row: Mapping[str, Any]) -> bytes:
    return hmac.new(key, canonical_row(table, row), hashlib.sha256).digest()


def verify(key: bytes, table: str, row: Mapping[str, Any]) -> bool:
    return hmac.compare_digest(compute(key, table, row), bytes(row["row_mac"]))
