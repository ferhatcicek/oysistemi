"""Kimlik bilgisi veren (Issuer): kimliği doğrulanmış seçmene TEK bir kör imza verir.

Issuer seçmenin kim olduğunu bilir ama imzaladığı şeyin (token) ne olduğunu bilmez.
"""
from __future__ import annotations

import hmac

from ..audit import chain
from ..context import Context
from ..crypto import blind_rsa, keystore, rowmac
from ..db.connection import IntegrityError, transaction
from ..elections.service import ElectionStateError, get_election, require_voting_window
from ..timekeeping import ClockError


class IssuanceError(RuntimeError):
    pass


class AlreadyIssued(IssuanceError):
    pass


def issue(ctx: Context, election_id: str, voter_id: str, blinded_msg: bytes) -> bytes:
    """Çağıran, voter_id'nin kimliğini önceden DOĞRULAMIŞ olmalıdır (auth katmanı).

    Aynı seçmen aynı körlenmiş mesajla tekrar gelirse (ör. ağ kesintisi) aynı imza döner;
    farklı bir mesajla gelirse reddedilir. Böylece hem imza kaybı telafi edilir hem de ikinci
    bir token alınamaz.
    """
    with transaction(ctx.conn):
        e = get_election(ctx, election_id)
        try:
            require_voting_window(e)
        except (ElectionStateError, ClockError) as exc:
            raise IssuanceError(str(exc)) from None

        ev = ctx.conn.execute(
            "SELECT * FROM election_voters WHERE election_id = ? AND voter_id = ?",
            (election_id, voter_id)).fetchone()
        if ev is None:
            raise IssuanceError("voter is not on the roll for this election")
        if not rowmac.verify(ctx.keys.row_mac, "election_voters", dict(ev)):
            raise IntegrityError("roll entry MAC invalid (possible unauthorised insertion)")
        v = ctx.conn.execute("SELECT * FROM voters WHERE id = ?", (voter_id,)).fetchone()
        if v is None or not rowmac.verify(ctx.keys.row_mac, "voters", dict(v)):
            raise IntegrityError("voter row MAC invalid")
        if v["status"] != "active":
            raise IssuanceError("voter is disabled")

        prev = ctx.conn.execute(
            "SELECT blinded_msg, blind_sig FROM credential_issuance "
            "WHERE election_id = ? AND voter_id = ?", (election_id, voter_id)).fetchone()
        if prev is not None:
            if hmac.compare_digest(prev["blinded_msg"], blinded_msg):
                return prev["blind_sig"]
            raise AlreadyIssued("a credential was already issued to this voter")

        sk = keystore.unwrap_private_key(ctx.keys.wrap, election_id, e["privkey_wrapped"])
        blind_sig = blind_rsa.blind_sign(sk, blinded_msg)
        # Ana zincire değil oylamanın kendi seçmen zincirine: katılım bitişe kadar sızmasın.
        chain.record_voter_event(ctx.conn, ctx.keys, election_id, voter_id,
                                 "credential_issued", {})
        # PRIMARY KEY (election_id, voter_id) eşzamanlı ikinci isteği DB düzeyinde de keser.
        ctx.conn.execute("INSERT INTO credential_issuance (election_id, voter_id, blinded_msg, "
                         "blind_sig) VALUES (?, ?, ?, ?)",
                         (election_id, voter_id, blinded_msg, blind_sig))
        return blind_sig
