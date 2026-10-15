from __future__ import annotations

import pytest

from oysistemi.elections import ballot_types as bt
from oysistemi.elections.ballot_types import InvalidBallot


def test_multi_bounds():
    t, cfg = bt.get("multi"), {"options": ["a", "b", "c"], "min_choices": 1, "max_choices": 2}
    t.validate_config(cfg)
    t.validate({"choices": ["a", "c"]}, cfg)
    for bad in ({"choices": []}, {"choices": ["a", "b", "c"]}, {"choices": ["a", "a"]},
                {"choices": ["z"]}):
        with pytest.raises(InvalidBallot):
            t.validate(bad, cfg)
    assert t.tally([{"choices": ["a"]}, {"choices": ["a", "b"]}], cfg)["counts"] == \
        {"a": 2, "b": 1, "c": 0}


def test_yes_no():
    t = bt.get("yes_no")
    t.validate_config({})
    t.validate({"choice": "çekimser"}, {})
    with pytest.raises(InvalidBallot):
        t.validate({"choice": None}, {})


def test_borda():
    t, cfg = bt.get("borda"), {"options": ["a", "b", "c"]}
    r = t.tally([{"ranking": ["a", "b", "c"]}, {"ranking": ["b", "a", "c"]},
                 {"ranking": ["b", "c", "a"]}], cfg)
    assert r["points"] == {"a": 3, "b": 5, "c": 1} and r["winners"] == ["b"]


def test_irv_without_ties():
    t, cfg = bt.get("ranked_irv"), {"options": ["a", "b", "c"]}
    ballots = ([{"ranking": ["a", "b"]}] * 4 + [{"ranking": ["b", "a"]}] * 3
               + [{"ranking": ["c", "b"]}] * 2)
    r = t.tally(ballots, cfg)
    assert r["eliminated"] == ["c"] and r["winner"] == "b"


def test_irv_elimination_tie():
    """Eşitlik bozma kuralı belirlenene kadar bu test başarısız olur (bkz. ranked.py)."""
    t, cfg = bt.get("ranked_irv"), {"options": ["a", "b", "c", "d"]}
    ballots = ([{"ranking": ["a"]}] * 3 + [{"ranking": ["b"]}] * 3
               + [{"ranking": ["c", "a"]}] + [{"ranking": ["d", "b"]}])
    r = t.tally(ballots, cfg)
    assert r["eliminated"][0] in ("c", "d") and r["winner"] in ("a", "b")
