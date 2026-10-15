"""İki kişi kuralı ve seçim durum makinesi."""
from __future__ import annotations

import pytest
from conftest import approve, at

from oysistemi.admin import governance as gov
from oysistemi.elections import service
from oysistemi.elections.ballot_types import ConfigError


def test_proposer_cannot_approve_own_request(ctx):
    rid = gov.propose(ctx, "a1", "voter_add", {"id": "v1", "display_name": "V1"})
    with pytest.raises(gov.GovernanceError, match="proposer"):
        gov.decide(ctx, "a1", rid, "approve")
    assert ctx.conn.execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0


def test_rejection_drops_request(ctx):
    rid = gov.propose(ctx, "a1", "voter_add", {"id": "v1", "display_name": "V1"})
    assert gov.decide(ctx, "a2", rid, "reject") == "rejected"
    with pytest.raises(gov.GovernanceError, match="already rejected"):
        gov.decide(ctx, "a2", rid, "approve")
    assert ctx.conn.execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0


def test_bootstrap_only_once_and_needs_two(ctx):
    with pytest.raises(gov.GovernanceError):
        gov.bootstrap_admins(ctx, [("x", "x", "p"), ("y", "y", "p")])


def test_proposer_cannot_set_new_admin_credentials(ctx):
    """Regresyon (güvenlik incelemesi): öneren, yeni hesabın parolasını belirleyememeli."""
    with pytest.raises(gov.GovernanceError, match="credentials are set by the new admin"):
        gov.propose(ctx, "a1", "admin_add", {"id": "a3", "username": "u",
                                             "pw_hash": gov.hash_password("x" * 12)})


def test_config_frozen_after_open(ctx, open_election):
    with pytest.raises(service.ElectionStateError):
        service.update_election(ctx, "a1", open_election, title="Değişti")


def test_cannot_open_with_roll_smaller_than_min_turnout(ctx):
    approve(ctx, "voter_add", {"id": "v1", "display_name": "V1"})
    service.create_election(ctx, "a1", "e9", "X", "single",
                            {"ballot": {"options": ["a", "b"]}, "min_turnout": 5,
                             "closes_at": at(3600)})
    approve(ctx, "roll_add", {"election_id": "e9", "voter_ids": ["v1"]})
    rid = gov.propose(ctx, "a1", "election_open", {"election_id": "e9"})
    with pytest.raises(ConfigError):
        gov.decide(ctx, "a2", rid, "approve")
    assert service.get_election(ctx, "e9")["status"] == "draft"


def test_invalid_config_rejected(ctx):
    with pytest.raises(ConfigError):
        service.create_election(ctx, "a1", "e3", "X", "multi",
                                {"ballot": {"options": ["a", "b"], "max_choices": 5},
                                 "closes_at": at(3600)})
    with pytest.raises(ConfigError):
        service.create_election(ctx, "a1", "e3", "X", "single",
                                {"ballot": {"options": ["a"]}, "closes_at": at(3600)})


def test_enrollment_code_expires_by_trusted_clock(ctx, clock):
    from oysistemi.admin import enrollment
    part_a = enrollment.new_part()
    rid = gov.propose(ctx, "a1", "admin_add", {"id": "z", "username": "z", "role": "admin",
                                               "enroll_a_hash": enrollment.hash_part(part_a)})
    gov.decide(ctx, "a2", rid, "approve")
    part_b = ctx.outputs.pop("enroll_b")["part"]
    clock.system_offset = -30 * 86400  # sistem saatini geri almak süreyi uzatmaz
    clock.advance(8 * 86400)
    with pytest.raises(enrollment.EnrollmentError, match="expired"):
        enrollment.complete(ctx, "z", part_a, part_b, "yeterince-uzun-parola")


def _draft_with_roll(ctx):
    for v in ("v1", "v2", "v3"):
        approve(ctx, "voter_add", {"id": v, "display_name": v})
    service.create_election(ctx, "a1", "e5", "Başkan", "single",
                            {"ballot": {"options": ["Ali", "Veli"]}, "min_turnout": 2,
                             "closes_at": at(3600)})
    approve(ctx, "roll_add", {"election_id": "e5", "voter_ids": ["v1", "v2"]})


def test_config_changed_after_open_proposal_is_not_sealed(ctx):
    """Regresyon (güvenlik incelemesi): onaydan önce taslak değişirse açılış reddedilir."""
    _draft_with_roll(ctx)
    rid = gov.propose(ctx, "a1", "election_open", {"election_id": "e5"})
    # Öneren, onaydan önce bitişi uzatıp seçeneği değiştiriyor
    service.update_election(ctx, "a1", "e5", cfg={"ballot": {"options": ["Ali", "Hile"]},
                                                  "min_turnout": 2, "closes_at": at(99999)})
    with pytest.raises(service.ElectionStateError, match="modified after the open proposal"):
        gov.decide(ctx, "a2", rid, "approve")
    assert service.get_election(ctx, "e5")["status"] == "draft"


def test_roll_changed_after_open_proposal_is_not_sealed(ctx):
    _draft_with_roll(ctx)
    rid = gov.propose(ctx, "a1", "election_open", {"election_id": "e5"})
    approve(ctx, "roll_add", {"election_id": "e5", "voter_ids": ["v3"]}, proposer="a2",
            approver="a1")
    with pytest.raises(service.ElectionStateError, match="roll_hash"):
        gov.decide(ctx, "a2", rid, "approve")


def test_client_cannot_forge_open_binding(ctx):
    """Bağlama sunucuda hesaplanır; istemcinin gönderdiği özet yok sayılır."""
    _draft_with_roll(ctx)
    rid = gov.propose(ctx, "a1", "election_open",
                      {"election_id": "e5", "config_hash": "0" * 64, "roll_hash": "0" * 64})
    assert gov.decide(ctx, "a2", rid, "approve") == "applied"
    assert service.get_election(ctx, "e5")["status"] == "open"
