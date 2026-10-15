"""Gereksinim 5: yetkisiz ekleme/silme engellenir; kurcalama ayak iziyle tespit edilir.

Saldırgan modeli: DB dosyasına doğrudan erişimi olan biri (ör. sqlite3 CLI), ancak DB
dışında tutulan ana anahtara erişimi yok.
"""
from __future__ import annotations

import sqlite3

import pytest
from conftest import approve
from helpers import get_credential

from oysistemi.audit import verifier
from oysistemi.voting import ballot_box


def raw(settings):
    """Uygulamayı atlayan saldırgan bağlantısı."""
    c = sqlite3.connect(settings.db_path, isolation_level=None)
    c.execute("PRAGMA foreign_keys = ON")
    return c


def codes(ctx):
    return {f.code for f in verifier.verify(ctx.conn, ctx.keys, ctx.settings.checkpoint_path)
            if f.severity == "critical"}


def test_clean_system_has_no_findings(ctx, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    assert codes(ctx) == set()


def test_direct_voter_insert_is_detected(ctx, settings):
    raw(settings).execute("INSERT INTO voters VALUES ('evil', 'Sahte', NULL, 'active', "
                          "'2026-01-01T00:00:00Z', x'00')")
    assert {"row_mac", "out_of_band", "checkpoint"} <= codes(ctx)


def test_voter_delete_is_blocked(ctx, settings):
    approve(ctx, "voter_add", {"id": "v1", "display_name": "V1"})
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        raw(settings).execute("DELETE FROM voters WHERE id = 'v1'")


def test_voter_delete_with_dropped_trigger_is_detected(ctx, settings):
    approve(ctx, "voter_add", {"id": "v1", "display_name": "V1"})
    c = raw(settings)
    c.execute("DROP TRIGGER voters_no_delete")
    c.execute("DELETE FROM voters WHERE id = 'v1'")
    found = codes(ctx)
    assert "schema" in found and "checkpoint" in found


def test_frozen_roll_cannot_be_changed(ctx, settings, open_election):
    c = raw(settings)
    with pytest.raises(sqlite3.IntegrityError, match="frozen"):
        c.execute("INSERT INTO election_voters VALUES ('e1', 'outsider', x'00')")
    with pytest.raises(sqlite3.IntegrityError, match="frozen"):
        c.execute("DELETE FROM election_voters WHERE voter_id = 'v1'")


def test_roll_change_bypassing_triggers_is_detected(ctx, settings, open_election):
    c = raw(settings)
    c.execute("DROP TRIGGER election_voters_frozen_ins")
    c.execute("INSERT INTO election_voters VALUES ('e1', 'outsider', x'00')")
    assert {"schema", "row_mac", "roll_changed", "out_of_band"} <= codes(ctx)


def test_forged_roll_row_cannot_obtain_credential(ctx, settings, open_election):
    c = raw(settings)
    c.execute("DROP TRIGGER election_voters_frozen_ins")
    c.execute("INSERT INTO election_voters VALUES ('e1', 'outsider', x'00')")
    from oysistemi.db.connection import IntegrityError
    with pytest.raises(IntegrityError):
        get_credential(ctx, "e1", "outsider")


def test_audit_log_is_append_only(ctx, settings):
    c = raw(settings)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        c.execute("DELETE FROM audit_log WHERE seq = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        c.execute("UPDATE audit_log SET actor = 'x' WHERE seq = 1")


def test_audit_log_rewrite_is_detected(ctx, settings):
    c = raw(settings)
    c.execute("DROP TRIGGER audit_log_no_update")
    c.execute("UPDATE audit_log SET actor = 'kimse' WHERE seq = 1")
    assert "audit_chain" in codes(ctx)


def test_ballot_stuffing_is_detected(ctx, settings, open_election):
    c = raw(settings)
    c.execute("INSERT INTO ballots VALUES ('e1', x'aa', x'bb', x'cc', '{\"choice\":\"Ali\"}')")
    assert {"forged_ballot", "ballot_stuffing"} <= codes(ctx)


def test_ballots_cannot_be_deleted(ctx, settings, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        raw(settings).execute("DELETE FROM ballots")


def test_tampered_external_checkpoint_is_detected(ctx, settings):
    path = settings.checkpoint_path
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[-1] = lines[-1].replace('\\"count\\":2', '\\"count\\":3')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert "checkpoint" in codes(ctx)


def test_app_refuses_to_start_with_modified_schema(ctx, settings):
    from oysistemi.context import LockedError, open_context
    raw(settings).execute("DROP TRIGGER ballots_no_delete")
    with pytest.raises(LockedError):
        open_context(settings)
