"""Sandık (BallotBox): kimlik SORMAZ; yalnızca geçerli kör imzalı token kabul eder.

Burada hiçbir şekilde denetim kaydı, zaman damgası ya da seçmen bilgisi tutulmaz. Tek bir
log satırı bile oy ile seçmen arasında zaman bağıntısı kurmaya yeter.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from ..audit import chain
from ..context import Context
from ..crypto import blind_rsa, fieldenc, keystore
from ..db.connection import transaction
from ..elections import ballot_types
from ..elections.service import ElectionStateError, get_election, require_voting_window
from ..timekeeping import ClockError

MAX_BALLOT_BYTES = 8192


def ballot_aad(election_id: str, token_hash: bytes) -> str:
    return f"ballots.ballot/{election_id}/{token_hash.hex()}"


class CastError(RuntimeError):
    pass


class AlreadyVoted(CastError):
    pass


def cast(ctx: Context, election_id: str, token: bytes, sig: bytes, ballot: Any) -> str:
    """Oyu sandığa atar; makbuz (token_hash, hex) döner."""
    if not isinstance(token, bytes) or not 32 < len(token) <= 256:
        raise CastError("malformed token")
    encoded = json.dumps(ballot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode()) > MAX_BALLOT_BYTES:
        raise CastError("ballot too large")
    token_hash = hashlib.sha256(token).digest()

    with transaction(ctx.conn):
        e = get_election(ctx, election_id)
        try:
            # Oy atma denetim kaydı yazmaz (gizlilik), ama saat geri alınmışsa yine durur.
            chain.check_high_water(ctx.conn)
            require_voting_window(e)
        except (ElectionStateError, ClockError) as exc:
            raise CastError(str(exc)) from None
        pk = keystore.load_public_pem(e["pubkey_pem"])
        if not blind_rsa.verify(pk, token, sig):
            raise CastError("invalid credential signature")
        cfg = json.loads(e["config"])
        try:
            ballot_types.get(e["ballot_type"]).validate(ballot, cfg["ballot"])
        except ballot_types.InvalidBallot as exc:
            raise CastError(f"invalid ballot: {exc}") from None
        try:
            # Oy içeriği şifreli: DB dosyası çalınsa bile ara sonuç okunamaz. AAD oyu bu
            # token'a bağlar; şifreli oy başka bir satıra taşınamaz.
            sealed = fieldenc.encrypt(ctx.keys.field, ballot_aad(election_id, token_hash), encoded)
            ctx.conn.execute("INSERT INTO ballots (election_id, token_hash, token, sig, ballot) "
                             "VALUES (?, ?, ?, ?, ?)", (election_id, token_hash, token, sig,
                                                        sealed))
        except sqlite3.IntegrityError:
            raise AlreadyVoted("this credential has already been used") from None
    return token_hash.hex()
