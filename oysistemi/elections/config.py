"""Seçim yapılandırması: oy türünden bağımsız ortak ayarlar + oy türüne özel ayarlar.

Yapılandırma yalnızca 'draft' durumunda değişir; seçim açılırken kanonik JSON'unun hash'i
mühürlenir (config_hash) ve DB tetikleyicisi sonraki değişiklikleri engeller.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from . import ballot_types
from .ballot_types import ConfigError

# Seçmen giriş yöntemleri. Yalnızca UYGULANMIŞ yöntemler burada olabilir: aksi halde
# seçmenlerin giriş yapamadığı bir oylama açılabilirdi.
AUTH_METHODS = {"printed_code", "email_otp"}

MIN_DURATION_SECONDS = 60

DEFAULTS: dict[str, Any] = {
    "opens_at": None,     # None: onay anında başlar
    "closes_at": None,    # ZORUNLU: bu andan önce kapanış/sayım/katılım bilgisi yok
    "min_turnout": 3,
    "auth_methods": ["printed_code", "email_otp"],
    "randomize_order": True,
}


def normalize(ballot_type: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Varsayılanları uygular ve tüm yapılandırmayı doğrular. Hatalıysa ConfigError."""
    if not isinstance(cfg, dict):
        raise ConfigError("config must be an object")
    allowed = set(DEFAULTS) | {"ballot"}
    extra = set(cfg) - allowed
    if extra:
        raise ConfigError(f"unknown config keys: {sorted(extra)}")
    out = {**DEFAULTS, **cfg}
    out.setdefault("ballot", {})

    mt = out["min_turnout"]
    if not isinstance(mt, int) or isinstance(mt, bool) or mt < 1:
        raise ConfigError("min_turnout must be an integer >= 1")
    methods = out["auth_methods"]
    if not isinstance(methods, list) or not methods or not set(methods) <= AUTH_METHODS:
        raise ConfigError(f"auth_methods must be a non-empty subset of {sorted(AUTH_METHODS)}")
    if not isinstance(out["randomize_order"], bool):
        raise ConfigError("randomize_order must be a boolean")

    closes = _parse_time(out["closes_at"], "closes_at", required=True)
    opens = _parse_time(out["opens_at"], "opens_at", required=False)
    if opens is not None and (closes - opens).total_seconds() < MIN_DURATION_SECONDS:
        raise ConfigError("closes_at must be at least one minute after opens_at")

    ballot_types.get(ballot_type).validate_config(out["ballot"])
    return out


def _parse_time(value: Any, name: str, *, required: bool) -> datetime | None:
    if value is None:
        if required:
            raise ConfigError(f"{name} is required (UTC, YYYY-MM-DDTHH:MM:SSZ)")
        return None
    from ..timekeeping import parse_iso
    try:
        return parse_iso(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be UTC in the form YYYY-MM-DDTHH:MM:SSZ") from None


def canonical(cfg: dict[str, Any]) -> str:
    return json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def config_hash(ballot_type: str, cfg: dict[str, Any]) -> str:
    return hashlib.sha256(f"{ballot_type}\n{canonical(cfg)}".encode()).hexdigest()
