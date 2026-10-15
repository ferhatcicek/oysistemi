"""Zaman güvenliği: saat manipülasyonu ve bitişe kadar mühürlü katılım/sonuç."""
from __future__ import annotations

import sqlite3

import pytest
from conftest import START, approve, at
from helpers import get_credential

from oysistemi.admin import governance as gov
from oysistemi.audit import chain, verifier
from oysistemi.elections import service
from oysistemi.timekeeping import ClockError, TrustedClock
from oysistemi.voting import ballot_box, issuer

# ───────────────────────── Güvenilir saat birimi ─────────────────────────


def ntp_clock(answers: dict[str, float], system_offset: float = 0.0) -> TrustedClock:
    """answers: kaynak → (gerçek zamana göre) sapma. Yanıt vermeyenler OSError."""
    t = [START]

    def query(host):
        if host not in answers:
            raise OSError("timeout")
        return t[0] + answers[host]

    return TrustedClock(mode="ntp", sources=("a", "b", "c", "d"), quorum=2, tolerance=30,
                        query=query, wall=lambda: t[0] + system_offset, mono=lambda: t[0])


def test_ntp_consensus_overrides_wrong_system_clock():
    c = ntp_clock({"a": 0, "b": 1, "c": -1}, system_offset=+7200)  # sistem saati 2 saat ileri
    assert c.sync() and c.assurance == "ntp"
    assert abs(c.now() - START) < 2  # uygulama zamanı gerçek zaman
    assert any(a.kind == "system_clock_wrong" for a in c.alarms)


def test_single_lying_source_is_outvoted():
    c = ntp_clock({"a": 0, "b": 0, "c": 0, "d": +86400})  # biri 1 gün ileri yalan söylüyor
    assert c.sync() and abs(c.now() - START) < 2


def test_disagreeing_sources_are_not_trusted():
    c = ntp_clock({"a": 0, "b": 5000, "c": -5000})
    assert not c.sync() and c.assurance == "unverified"
    with pytest.raises(ClockError):
        c.require_trusted()


def test_unreachable_sources_leave_time_unverified():
    c = ntp_clock({"a": 0})  # yalnızca bir kaynak yanıt veriyor < quorum
    assert not c.sync() and c.assurance == "unverified"


def test_changing_system_clock_at_runtime_does_not_move_app_time(clock):
    before = clock.now()
    clock.system_offset = 3 * 86400  # biri sistem saatini 3 gün ileri aldı
    assert abs(clock.now() - before) < 1  # uygulama zamanı monotonik sayaçla akar
    clock.check_jump()
    assert any(a.kind == "system_clock_jump" for a in clock.alarms)


# ───────────────────────── Oylama penceresi ─────────────────────────

def test_election_cannot_be_closed_before_scheduled_end(ctx, clock, open_election):
    rid = gov.propose(ctx, "a1", "election_close", {"election_id": open_election})
    with pytest.raises(service.ElectionStateError, match="scheduled end"):
        gov.decide(ctx, "a2", rid, "approve")  # iki yönetici birlikte bile kapatamaz
    e = service.get_election(ctx, open_election)
    assert e["status"] == "open" and e["result"] is None
    with pytest.raises(service.ElectionStateError):
        service.bulletin(ctx, open_election)


def test_forwarding_system_clock_does_not_allow_early_close(ctx, clock, open_election):
    clock.system_offset = 2 * 3600  # sistem saati bitişin ötesine alındı
    rid = gov.propose(ctx, "a1", "election_close", {"election_id": open_election})
    with pytest.raises(service.ElectionStateError):
        gov.decide(ctx, "a2", rid, "approve")
    assert service.close_due_elections(ctx) == []


def test_auto_close_exactly_after_end(ctx, clock, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    clock.advance(3599)
    assert service.close_due_elections(ctx) == []
    clock.advance(2)
    assert service.close_due_elections(ctx) == [open_election]
    e = service.get_election(ctx, open_election)
    assert e["status"] == "tallied" and e["privkey_wrapped"] is None
    row = ctx.conn.execute("SELECT actor FROM audit_log WHERE action = 'election_auto_close'"
                           ).fetchone()
    assert row["actor"] == "system"


def test_unverified_clock_postpones_closing(ctx, clock, open_election):
    clock.advance(4000)
    clock.assurance = "unverified"
    assert service.close_due_elections(ctx) == []
    rid = gov.propose(ctx, "a1", "election_close", {"election_id": open_election})
    with pytest.raises(ClockError):
        gov.decide(ctx, "a2", rid, "approve")
    clock.assurance = "ntp"
    assert service.close_due_elections(ctx) == [open_election]


def test_no_voting_before_open_or_after_end(ctx, clock):
    for v in ("v1", "v2"):
        approve(ctx, "voter_add", {"id": v, "display_name": v})
    service.create_election(ctx, "a1", "later", "Sonra", "yes_no",
                            {"min_turnout": 1, "opens_at": at(600), "closes_at": at(1200)})
    approve(ctx, "roll_add", {"election_id": "later", "voter_ids": ["v1", "v2"]})
    approve(ctx, "election_open", {"election_id": "later"})
    with pytest.raises(issuer.IssuanceError, match="not started"):
        get_credential(ctx, "later", "v1")
    clock.advance(700)
    token, sig = get_credential(ctx, "later", "v1")  # pencere içinde
    clock.advance(600)
    with pytest.raises(ballot_box.CastError, match="ended"):
        ballot_box.cast(ctx, "later", token, sig, {"choice": "evet"})
    with pytest.raises(issuer.IssuanceError, match="ended"):
        get_credential(ctx, "later", "v2")


def test_cannot_open_election_whose_end_has_passed(ctx, clock):
    approve(ctx, "voter_add", {"id": "v1", "display_name": "v1"})
    service.create_election(ctx, "a1", "old", "Eski", "yes_no",
                            {"min_turnout": 1, "closes_at": at(60)})
    approve(ctx, "roll_add", {"election_id": "old", "voter_ids": ["v1"]})
    clock.advance(120)
    rid = gov.propose(ctx, "a1", "election_open", {"election_id": "old"})
    with pytest.raises(Exception, match="past"):
        gov.decide(ctx, "a2", rid, "approve")


def test_end_time_is_required_and_sealed(ctx, open_election):
    from oysistemi.elections.ballot_types import ConfigError
    with pytest.raises(ConfigError, match="closes_at"):
        service.create_election(ctx, "a1", "x", "X", "yes_no", {"min_turnout": 1})
    with pytest.raises(service.ElectionStateError):  # açıldıktan sonra uzatılamaz/kısaltılamaz
        service.update_election(ctx, "a1", open_election,
                                cfg={"ballot": {"options": ["Ali", "Veli"]}, "closes_at": at(60)})


# ───────────────────────── Saat geri alma (rollback) ─────────────────────────

def test_clock_rollback_after_restart_suspends_voting(ctx, clock, open_election):
    """Sunucu, sistem saati 1 saat geri alınmış olarak yeniden başlatıldı."""
    token, sig = get_credential(ctx, open_election, "v1")
    clock.t -= 3600  # yeni süreç yanlış duvar saatine çapalandı
    with pytest.raises(ballot_box.CastError, match="rollback"):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    with pytest.raises(issuer.IssuanceError, match="tampering"):
        get_credential(ctx, open_election, "v2")
    findings = verifier.verify(ctx.conn, ctx.keys, ctx.settings.checkpoint_path)
    assert any(f.code == "clock" and f.severity == "critical" for f in findings)


def test_backdated_audit_entry_is_blocked_and_detected(ctx, settings):
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    last = raw.execute("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC").fetchone()
    with pytest.raises(sqlite3.IntegrityError, match="backwards"):
        raw.execute("INSERT INTO audit_log VALUES (?, '2000-01-01T00:00:00Z', 'x', 'y', '{}', ?, "
                    "'h', 'm')", (last[0] + 1, last[1]))
    raw.execute("DROP TRIGGER audit_log_monotonic_ts")
    raw.execute("INSERT INTO audit_log VALUES (?, '2000-01-01T00:00:00Z', 'x', 'y', '{}', ?, "
                "'h', 'm')", (last[0] + 1, last[1]))
    problems = chain.verify_chain(ctx.conn, ctx.keys.audit)
    assert any("backwards" in p for p in problems)


# ───────────────────────── Bitişe kadar katılım mühürlü ─────────────────────────

def test_integrity_findings_hide_counts_while_open(ctx, settings, open_election):
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    raw.execute("INSERT INTO ballots VALUES ('e1', x'aa', x'bb', x'cc', '{\"choice\":\"Ali\"}')")
    msgs = [f.detail for f in verifier.verify(ctx.conn, ctx.keys, settings.checkpoint_path)
            if f.code in ("ballot_stuffing", "forged_ballot")]
    assert msgs and all(not any(ch.isdigit() for ch in m.replace("e1", "")) for m in msgs)


def test_voter_activity_leaves_no_gap_in_main_audit_sequence(ctx, settings, open_election):
    """Regresyon: seçmen olayları ana zincirde olsaydı sıra boşluğu katılımı ele verirdi."""
    import json as _json
    before = ctx.conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    cp_before = settings.checkpoint_path.read_text(encoding="utf-8").splitlines()[-1]
    for v in ("v1", "v2"):
        token, sig = get_credential(ctx, open_election, v)
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    assert ctx.conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0] == before
    # Harici checkpoint'teki audit_seq de değişmez
    from oysistemi.audit import checkpoint
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, settings.checkpoint_path)
    last = settings.checkpoint_path.read_text(encoding="utf-8").splitlines()[-1]
    seq = lambda line: _json.loads(_json.loads(line)["body"])["audit_seq"]  # noqa: E731
    assert seq(last) == seq(cp_before)


def test_voter_log_is_sealed_at_close_and_tamper_detected(ctx, clock, settings, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    get_credential(ctx, open_election, "v2")
    clock.advance(3601)
    assert service.close_due_elections(ctx) == [open_election]
    crit = lambda: {f.code for f in verifier.verify(  # noqa: E731
        ctx.conn, ctx.keys, settings.checkpoint_path) if f.severity == "critical"}
    assert crit() == set()
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    raw.execute("DROP TRIGGER voter_log_no_delete")
    raw.execute("DELETE FROM voter_log WHERE election_id = 'e1' AND seq = "
                "(SELECT MAX(seq) FROM voter_log WHERE election_id = 'e1')")
    assert "voter_log" in crit()


def test_issuance_without_voter_log_entry_is_detected(ctx, settings, open_election):
    get_credential(ctx, open_election, "v1")
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    raw.execute("PRAGMA foreign_keys = ON")
    raw.execute("INSERT INTO credential_issuance VALUES ('e1', 'v2', x'01', x'02')")
    findings = verifier.verify(ctx.conn, ctx.keys, settings.checkpoint_path)
    assert any(f.code == "voter_log" for f in findings)
