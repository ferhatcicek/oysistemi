"""Sıralı oy türleri: Borda ve Anında Yeniden Sayım (IRV)."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .base import BallotType, ConfigError, InvalidBallot, require_exact_keys, validate_options


class _Ranked(BallotType):
    def validate_config(self, cfg: dict[str, Any]) -> None:
        validate_options(cfg)
        if not isinstance(cfg.get("require_full_ranking", False), bool):
            raise ConfigError("'require_full_ranking' must be a boolean")

    def validate(self, ballot: Any, cfg: dict[str, Any]) -> None:
        require_exact_keys(ballot, {"ranking"}, InvalidBallot)
        ranking = ballot["ranking"]
        opts = self.options(cfg)
        if not isinstance(ranking, list) or any(r not in opts for r in ranking):
            raise InvalidBallot("ranking must list known options")
        if len(set(ranking)) != len(ranking):
            raise InvalidBallot("an option may be ranked only once")
        if cfg.get("require_full_ranking", False) and len(ranking) != len(opts):
            raise InvalidBallot("all options must be ranked")
        if not ranking:
            raise InvalidBallot("rank at least one option")


class Borda(_Ranked):
    name = "borda"
    description = "Borda sayımı: n seçenekte 1. sıra n-1, son sıra 0 puan alır."

    def tally(self, ballots: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
        opts = self.options(cfg)
        n = len(opts)
        points = {o: 0 for o in opts}
        for b in ballots:
            for i, o in enumerate(b["ranking"]):
                points[o] += n - 1 - i
        ranked = sorted(points.items(), key=lambda kv: -kv[1])
        top = ranked[0][1] if ranked else 0
        return {"points": points, "ranking": [o for o, _ in ranked],
                "winners": [o for o, p in points.items() if p == top]}


def break_elimination_tie(tied: list[str], rounds: list[dict[str, int]],
                          ballots: list[dict[str, Any]]) -> str:
    """IRV'de en az oyu alan birden fazla aday varsa hangisinin eleneceğine karar verir.

    Parametreler:
        tied:    Bu turda eşit ve en düşük oyu alan adaylar (alfabetik sıralı, en az 2).
        rounds:  Şimdiye kadarki turların sayımları; rounds[0] ilk tercih sayımlarıdır,
                 rounds[-1] mevcut turdur.
        ballots: Tüm geçerli pusulalar (yayımlanan ilan panosuyla aynı veri).

    Dönüş: `tied` içinden elenecek TEK aday.

    KISIT: Sonuç bağımsız doğrulayıcı tarafından yeniden üretilebilmelidir. Rastgelelik
    kullanılacaksa `random.random()` DEĞİL, yayımlanan veriden türetilen deterministik bir
    tohum (ör. SHA-256(sıralı pusulalar)) kullanılmalıdır.
    """
    # 1) Geriye doğru bakış: eşitliği bozan en yakın önceki turda en az oyu alan elenir.
    candidates = list(tied)
    for counts in reversed(rounds[:-1]):
        low = min(counts.get(c, 0) for c in candidates)
        candidates = [c for c in candidates if counts.get(c, 0) == low]
        if len(candidates) == 1:
            return candidates[0]
    # 2) Hâlâ eşitse doğrulanabilir kura: tohum yayımlanan pusulalardan türetilir, herkes
    #    aynı sonucu yeniden hesaplayabilir ama oy vermeden önce kimse öngöremez.
    seed = hashlib.sha256("\n".join(sorted(
        json.dumps(b, sort_keys=True, ensure_ascii=False) for b in ballots)).encode()).digest()
    return min(candidates, key=lambda c: hashlib.sha256(seed + c.encode()).digest())


class InstantRunoff(_Ranked):
    name = "ranked_irv"
    description = "Anında yeniden sayım: salt çoğunluk sağlanana dek en az oyu alan elenir."

    def tally(self, ballots: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
        remaining = set(self.options(cfg))
        rounds: list[dict[str, int]] = []
        eliminated: list[str] = []
        while True:
            counts = {o: 0 for o in sorted(remaining)}
            exhausted = 0
            for b in ballots:
                pick = next((o for o in b["ranking"] if o in remaining), None)
                if pick is None:
                    exhausted += 1
                else:
                    counts[pick] += 1
            rounds.append(counts)
            active = sum(counts.values())
            leader, lead_votes = max(counts.items(), key=lambda kv: kv[1])
            if active and lead_votes * 2 > active:
                return {"winner": leader, "rounds": rounds, "eliminated": eliminated,
                        "exhausted": exhausted}
            if len(remaining) == 1 or active == 0:
                return {"winner": None, "rounds": rounds, "eliminated": eliminated,
                        "exhausted": exhausted}
            low = min(counts.values())
            tied = [o for o, c in counts.items() if c == low]
            loser = tied[0] if len(tied) == 1 else break_elimination_tie(tied, rounds, ballots)
            if loser not in tied:
                raise RuntimeError("tie-break must return one of the tied candidates")
            remaining.discard(loser)
            eliminated.append(loser)
