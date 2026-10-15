from __future__ import annotations

from datetime import UTC, datetime

import pytest

from oysistemi.admin import governance as gov
from oysistemi.config import Settings
from oysistemi.context import initialise, open_context
from oysistemi.timekeeping import TrustedClock, set_clock

START = datetime(2026, 10, 15, 10, 0, tzinfo=UTC).timestamp()


class FakeClock(TrustedClock):
    """Testlerde zamanı elle ilerleten saat. wall = sistem saati, t = gerçek akış."""

    def __init__(self) -> None:
        self.t = START
        self.system_offset = 0.0  # sistem saatine yapılan "manipülasyon"
        super().__init__(mode="system", wall=lambda: self.t + self.system_offset,
                         mono=lambda: self.t)
        self.assurance = "ntp"

    def advance(self, seconds: float) -> None:
        self.t += seconds


def at(offset_seconds: float) -> str:
    """START'a göre UTC ISO zaman damgası."""
    return datetime.fromtimestamp(START + offset_seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(autouse=True)
def clock():
    c = FakeClock()
    set_clock(c)
    yield c
    set_clock(TrustedClock(mode="system"))


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "data" / "oys.db",
                    master_key_path=tmp_path / "secrets" / "master.key",
                    checkpoint_path=tmp_path / "cp" / "checkpoints.jsonl",
                    rsa_bits=2048)


@pytest.fixture
def ctx(settings):
    initialise(settings)
    c = open_context(settings)
    gov.bootstrap_admins(c, [("a1", "ayse", "pw-ayse-123"), ("a2", "mehmet", "pw-mehmet-123")])
    yield c
    c.close()


def close(ctx, clock, election_id):
    """Bitiş zamanını geçip iki onayla kapat."""
    clock.advance(3601)
    approve(ctx, "election_close", {"election_id": election_id})


def approve(ctx, kind, payload, proposer="a1", approver="a2"):
    rid = gov.propose(ctx, proposer, kind, payload)
    assert gov.decide(ctx, approver, rid, "approve") == "applied"
    return rid


@pytest.fixture
def open_election(ctx):
    """3 seçmenli, açık bir tek-seçim seçimi."""
    from oysistemi.elections import service

    for vid in ("v1", "v2", "v3"):
        approve(ctx, "voter_add", {"id": vid, "display_name": vid.upper()})
    approve(ctx, "voter_add", {"id": "outsider", "display_name": "Dışarıdan"})
    service.create_election(ctx, "a1", "e1", "Başkan seçimi", "single",
                            {"ballot": {"options": ["Ali", "Veli"], "allow_blank": True},
                             "min_turnout": 2, "closes_at": at(3600)})
    approve(ctx, "roll_add", {"election_id": "e1", "voter_ids": ["v1", "v2", "v3"]})
    approve(ctx, "election_open", {"election_id": "e1"})
    return "e1"
