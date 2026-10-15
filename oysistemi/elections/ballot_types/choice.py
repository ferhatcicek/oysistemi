"""Seçim tabanlı oy türleri: tek seçim, evet/hayır/çekimser, çoklu seçim, onay oylaması."""
from __future__ import annotations

from typing import Any

from .base import BallotType, ConfigError, InvalidBallot, require_exact_keys, validate_options


class SingleChoice(BallotType):
    name = "single"
    description = "Seçeneklerden yalnızca biri işaretlenir."

    def validate_config(self, cfg: dict[str, Any]) -> None:
        validate_options(cfg)
        if not isinstance(cfg.get("allow_blank", False), bool):
            raise ConfigError("'allow_blank' must be a boolean")

    def validate(self, ballot: Any, cfg: dict[str, Any]) -> None:
        require_exact_keys(ballot, {"choice"}, InvalidBallot)
        choice = ballot["choice"]
        if choice is None:
            if not cfg.get("allow_blank", False):
                raise InvalidBallot("blank ballots are not allowed")
        elif choice not in self.options(cfg):
            raise InvalidBallot("unknown option")

    def tally(self, ballots: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
        counts = {o: 0 for o in self.options(cfg)}
        blank = 0
        for b in ballots:
            if b["choice"] is None:
                blank += 1
            else:
                counts[b["choice"]] += 1
        top = max(counts.values(), default=0)
        winners = [o for o, c in counts.items() if c == top and top > 0]
        return {"counts": counts, "blank": blank, "winners": winners}


class YesNo(SingleChoice):
    name = "yes_no"
    description = "Evet / Hayır / Çekimser karar oylaması."
    OPTIONS = ["evet", "hayır", "çekimser"]

    def validate_config(self, cfg: dict[str, Any]) -> None:
        extra = set(cfg) - {"allow_blank"}
        if extra:
            raise ConfigError(f"yes_no takes no options; unexpected keys: {sorted(extra)}")

    def options(self, cfg: dict[str, Any]) -> list[str]:
        return list(self.OPTIONS)


class MultiChoice(BallotType):
    name = "multi"
    description = "En az min, en fazla max seçenek işaretlenir."

    def _bounds(self, cfg: dict[str, Any]) -> tuple[int, int]:
        n = len(cfg["options"])
        return cfg.get("min_choices", 0), cfg.get("max_choices", n)

    def validate_config(self, cfg: dict[str, Any]) -> None:
        opts = validate_options(cfg)
        lo, hi = self._bounds(cfg)
        if not (isinstance(lo, int) and isinstance(hi, int)) or isinstance(lo, bool) \
                or isinstance(hi, bool):
            raise ConfigError("min_choices/max_choices must be integers")
        if not 0 <= lo <= hi <= len(opts) or hi == 0:
            raise ConfigError("require 0 <= min_choices <= max_choices <= len(options), max >= 1")

    def validate(self, ballot: Any, cfg: dict[str, Any]) -> None:
        require_exact_keys(ballot, {"choices"}, InvalidBallot)
        choices = ballot["choices"]
        if not isinstance(choices, list) or len(set(map(str, choices))) != len(choices):
            raise InvalidBallot("'choices' must be a list without duplicates")
        if any(c not in self.options(cfg) for c in choices):
            raise InvalidBallot("unknown option")
        lo, hi = self._bounds(cfg)
        if not lo <= len(choices) <= hi:
            raise InvalidBallot(f"select between {lo} and {hi} options")

    def tally(self, ballots: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
        counts = {o: 0 for o in self.options(cfg)}
        blank = 0
        for b in ballots:
            if not b["choices"]:
                blank += 1
            for c in b["choices"]:
                counts[c] += 1
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])
        return {"counts": counts, "blank": blank, "ranking": [o for o, _ in ranked]}


class Approval(MultiChoice):
    name = "approval"
    description = "Onay oylaması: uygun bulunan tüm seçenekler işaretlenir."

    def _bounds(self, cfg: dict[str, Any]) -> tuple[int, int]:
        return 0, len(cfg["options"])

    def validate_config(self, cfg: dict[str, Any]) -> None:
        validate_options(cfg)
        extra = set(cfg) - {"options"}
        if extra:
            raise ConfigError(f"unexpected keys: {sorted(extra)}")
