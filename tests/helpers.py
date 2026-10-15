"""Testlerde tarayıcının yapacağı istemci tarafı adımları taklit eder."""
from __future__ import annotations

import secrets

from oysistemi.crypto import blind_rsa, keystore
from oysistemi.elections.service import get_election
from oysistemi.voting import issuer


def get_credential(ctx, election_id: str, voter_id: str) -> tuple[bytes, bytes]:
    pk = keystore.load_public_pem(get_election(ctx, election_id)["pubkey_pem"])
    token = blind_rsa.prepare(secrets.token_bytes(32))
    blinded, inv = blind_rsa.blind(pk, token)
    blind_sig = issuer.issue(ctx, election_id, voter_id, blinded)
    return token, blind_rsa.finalize(pk, token, blind_sig, inv)
