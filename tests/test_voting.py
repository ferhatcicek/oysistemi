"""Gereksinim 1–3: tek kişi tek oy, yalnızca listedekiler, bağlanamazlık."""
from __future__ import annotations

import secrets
import threading

import pytest
from conftest import approve, at, close
from helpers import get_credential

from oysistemi.context import open_context
from oysistemi.crypto import blind_rsa, keystore
from oysistemi.elections import service
from oysistemi.elections.service import get_election
from oysistemi.voting import ballot_box, issuer


def test_full_flow_and_result(ctx, clock, open_election):
    receipts = []
    for vid, choice in (("v1", "Ali"), ("v2", "Ali"), ("v3", "Veli")):
        token, sig = get_credential(ctx, open_election, vid)
        receipts.append(ballot_box.cast(ctx, open_election, token, sig, {"choice": choice}))
    close(ctx, clock, open_election)

    e = get_election(ctx, open_election)
    assert e["status"] == "tallied" and e["privkey_wrapped"] is None
    board = service.bulletin(ctx, open_election)
    assert board["result"]["tally"]["counts"] == {"Ali": 2, "Veli": 1}
    assert sorted(receipts) == board["receipts"]


# ───────────── Çift oy ─────────────

def test_same_credential_cannot_vote_twice(ctx, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    with pytest.raises(ballot_box.AlreadyVoted):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Veli"})


def test_voter_cannot_get_second_credential(ctx, open_election):
    get_credential(ctx, open_election, "v1")
    with pytest.raises(issuer.AlreadyIssued):
        get_credential(ctx, open_election, "v1")


def test_retry_with_same_blinded_message_is_idempotent(ctx, open_election):
    pk = keystore.load_public_pem(get_election(ctx, open_election)["pubkey_pem"])
    token = blind_rsa.prepare(b"x" * 32)
    blinded, inv = blind_rsa.blind(pk, token)
    s1 = issuer.issue(ctx, open_election, "v1", blinded)
    s2 = issuer.issue(ctx, open_election, "v1", blinded)  # ağ kesintisi sonrası tekrar
    assert s1 == s2
    blind_rsa.finalize(pk, token, s2, inv)


def test_concurrent_double_vote_race(ctx, settings, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    results, barrier = [], threading.Barrier(20)

    def worker():
        c = open_context(settings)
        barrier.wait()
        try:
            ballot_box.cast(c, open_election, token, sig, {"choice": "Ali"})
            results.append("ok")
        except ballot_box.AlreadyVoted:
            results.append("dup")
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1 and results.count("dup") == 19


def test_concurrent_double_issuance_race(ctx, settings, open_election):
    pk = keystore.load_public_pem(get_election(ctx, open_election)["pubkey_pem"])
    results, barrier = [], threading.Barrier(10)

    def worker():
        c = open_context(settings)
        blinded, _ = blind_rsa.blind(pk, blind_rsa.prepare(secrets.token_bytes(32)))
        barrier.wait()
        try:
            issuer.issue(c, open_election, "v2", blinded)
            results.append("ok")
        except issuer.AlreadyIssued:
            results.append("dup")
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1


# ───────────── Yalnızca listedekiler ─────────────

def test_voter_not_on_roll_is_refused(ctx, open_election):
    with pytest.raises(issuer.IssuanceError, match="not on the roll"):
        get_credential(ctx, open_election, "outsider")
    with pytest.raises(issuer.IssuanceError):
        get_credential(ctx, open_election, "nobody")


def test_self_made_signature_is_refused(ctx, open_election):
    fake_key = blind_rsa.generate_key(2048)
    token = blind_rsa.prepare(b"y" * 32)
    blinded, inv = blind_rsa.blind(fake_key.public_key(), token)
    sig = blind_rsa.finalize(fake_key.public_key(), token,
                             blind_rsa.blind_sign(fake_key, blinded), inv)
    with pytest.raises(ballot_box.CastError, match="invalid credential"):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})


def test_credential_from_other_election_is_refused(ctx, open_election):
    service.create_election(ctx, "a1", "e2", "Sayman", "yes_no",
                            {"min_turnout": 1, "closes_at": at(3600)})
    approve(ctx, "roll_add", {"election_id": "e2", "voter_ids": ["v1"]})
    approve(ctx, "election_open", {"election_id": "e2"})
    token, sig = get_credential(ctx, "e2", "v1")
    with pytest.raises(ballot_box.CastError, match="invalid credential"):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})


def test_ballot_with_extra_fields_is_refused(ctx, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    with pytest.raises(ballot_box.CastError):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali", "mark": "mavi-kedi"})


def test_no_votes_after_close(ctx, clock, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    close(ctx, clock, open_election)
    with pytest.raises(ballot_box.CastError):
        ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})


# ───────────── Bağlanamazlık ─────────────

def test_ballots_table_has_no_identifying_columns(ctx):
    cols = {r["name"] for r in ctx.conn.execute("PRAGMA table_info(ballots)")}
    assert cols == {"election_id", "token_hash", "token", "sig", "ballot"}
    # ROWID yok → ekleme sırası saklanmaz
    with pytest.raises(Exception):
        ctx.conn.execute("SELECT rowid FROM ballots")


def test_server_data_cannot_link_ballot_to_voter(ctx, open_election):
    """Sunucunun gördüğü her şey (blinded, blind_sig) ile sandıktaki (token, sig) eşleşmez."""
    get_credential(ctx, open_election, "v1")
    token, sig = get_credential(ctx, open_election, "v2")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    issued = ctx.conn.execute("SELECT blinded_msg, blind_sig FROM credential_issuance").fetchall()
    for row in issued:
        assert row["blind_sig"] != sig and row["blinded_msg"] != token
        assert token not in row["blinded_msg"] and sig not in row["blind_sig"]


def test_results_withheld_below_min_turnout(ctx, clock, open_election):
    token, sig = get_credential(ctx, open_election, "v1")
    ballot_box.cast(ctx, open_election, token, sig, {"choice": "Ali"})
    close(ctx, clock, open_election)
    board = service.bulletin(ctx, open_election)
    assert board["result"]["withheld"] is True
    assert "tally" not in board["result"] and "ballots" not in board
