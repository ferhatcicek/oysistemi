"""Oy türü eklenti arayüzü.

Her oy türü üç şeyi tanımlar: seçim yapılandırmasının doğrulanması, tek bir oy pusulasının
doğrulanması ve sayım. Yeni bir tür eklemek için BallotType'tan türetip REGISTRY'ye ekleyin.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConfigError(ValueError):
    pass


class InvalidBallot(ValueError):
    pass


def require_exact_keys(obj: Any, keys: set[str], err: type[ValueError]) -> None:
    """Pusulada beklenen alanlar DIŞINDA hiçbir şey olamaz.

    Serbest alanlara izin vermek "işaretli oy" açığı yaratır: seçmen pusulaya kendine özgü
    bir değer yazıp yayımlanan listede oyunu üçüncü kişiye ispatlayabilir (oy satışı).
    """
    if not isinstance(obj, dict) or set(obj) != keys:
        raise err(f"expected exactly the keys {sorted(keys)}")


def validate_options(cfg: dict[str, Any], min_options: int = 2) -> list[str]:
    opts = cfg.get("options")
    if not isinstance(opts, list) or len(opts) < min_options:
        raise ConfigError(f"'options' must be a list with at least {min_options} entries")
    if any(not isinstance(o, str) or not o.strip() for o in opts):
        raise ConfigError("options must be non-empty strings")
    if len(set(opts)) != len(opts):
        raise ConfigError("options must be unique")
    return opts


class BallotType(ABC):
    name: str
    description: str

    @abstractmethod
    def validate_config(self, cfg: dict[str, Any]) -> None: ...

    @abstractmethod
    def validate(self, ballot: Any, cfg: dict[str, Any]) -> None: ...

    @abstractmethod
    def tally(self, ballots: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]: ...

    def options(self, cfg: dict[str, Any]) -> list[str]:
        return list(cfg["options"])
