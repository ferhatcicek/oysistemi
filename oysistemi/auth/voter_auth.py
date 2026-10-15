"""Seçmen kimlik doğrulama: basılı tek kullanımlık kod ve e-posta OTP.

Her iki yöntemde de DB'de yalnızca argon2 hash'i durur; DB'yi okuyan biri kodları göremez.
Kod başına en fazla MAX_ATTEMPTS yanlış deneme yapılabilir, sonra kod kilitlenir.
Bir kod yalnızca bir kez kimlik bilgisi (kör imza) almaya yarar: Issuer ikinci imzayı vermez.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from ..audit import chain
from ..context import Context
from ..crypto import fieldenc, rowmac
from ..db.connection import IntegrityError, insert_row, transaction, update_row
from ..elections.service import ElectionStateError, get_election, require_voting_window, window
from ..timekeeping import ClockError, get_clock
from . import mailer

MAX_ATTEMPTS = 5
OTP_TTL = timedelta(minutes=10)
OTP_RESEND_AFTER = timedelta(seconds=60)
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 0/O, 1/I karışmasın
_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("dummy-code-for-constant-time")


class VoterAuthError(RuntimeError):
    pass


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _normalize(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def new_printed_code() -> str:
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))  # ~60 bit
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


def _allowed(e: dict[str, Any], method: str) -> None:
    try:
        require_voting_window(e)
    except (ElectionStateError, ClockError) as exc:
        raise VoterAuthError(str(exc)) from None
    if method not in json.loads(e["config"])["auth_methods"]:
        raise VoterAuthError(f"{method} is not enabled for this election")


def generate_printed_codes(ctx: Context, admin_id: str, election_id: str) -> list[dict[str, str]]:
    """Listede kodu olmayan her seçmen için bir kod üretir. Kodlar YALNIZCA burada döner.

    Kodları gören kişi o seçmenler adına giriş yapabilir: çıktıyı kapalı zarfta dağıtın.
    Aynı seçmene ikinci kez kod üretilmez (sessizce yeniden üretim = kimlik çalma riski).
    """
    from ..admin.governance import require_admin

    out = []
    with transaction(ctx.conn):
        require_admin(ctx, admin_id)
        e = get_election(ctx, election_id)
        # Kodlar oylama başlamadan önce de üretilebilir (zarfların önceden dağıtılması için),
        # ama liste mühürlenmiş olmalı (status=open) ve oylama bitmemiş olmalı.
        if e["status"] != "open" or window(e) == "after":
            raise VoterAuthError("codes can be generated only for an open, unfinished election")
        if "printed_code" not in json.loads(e["config"])["auth_methods"]:
            raise VoterAuthError("printed_code is not enabled for this election")
        rows = ctx.conn.execute(
            "SELECT ev.voter_id, v.display_name FROM election_voters ev "
            "JOIN voters v ON v.id = ev.voter_id WHERE ev.election_id = ? AND NOT EXISTS "
            "(SELECT 1 FROM auth_codes a WHERE a.election_id = ev.election_id "
            " AND a.voter_id = ev.voter_id AND a.method = 'printed_code') ORDER BY ev.voter_id",
            (election_id,)).fetchall()
        chain.record(ctx.conn, ctx.keys, admin_id, "printed_codes_generated",
                     {"election_id": election_id, "voter_ids": [r["voter_id"] for r in rows]})
        for r in rows:
            code = new_printed_code()
            insert_row(ctx.conn, ctx.keys.row_mac, "auth_codes", {
                "election_id": election_id, "voter_id": r["voter_id"], "method": "printed_code",
                "code_hash": _ph.hash(_normalize(code)), "expires_at": None, "attempts": 0,
                "used": 0})
            name = fieldenc.decrypt(ctx.keys.field, f"voters.display_name/{r['voter_id']}",
                                    r["display_name"])
            out.append({"voter_id": r["voter_id"], "display_name": name,
                        "code": code})
    return out


def request_email_otp(ctx: Context, election_id: str, voter_id: str) -> None:
    """Seçmen listede ve e-postası kayıtlıysa kod gönderir.

    Seçmen yoksa da sessizce döner: çağıran taraf her durumda aynı mesajı göstermelidir,
    böylece kimin listede olduğu dışarıdan sorgulanamaz.
    """
    with transaction(ctx.conn):
        e = get_election(ctx, election_id)
        _allowed(e, "email_otp")
        v = ctx.conn.execute(
            "SELECT v.* FROM voters v JOIN election_voters ev ON ev.voter_id = v.id "
            "WHERE ev.election_id = ? AND v.id = ? AND v.status = 'active'",
            (election_id, voter_id)).fetchone()
        if v is None or not v["email"]:
            return
        email = fieldenc.decrypt(ctx.keys.field, f"voters.email/{voter_id}", v["email"])
        if not rowmac.verify(ctx.keys.row_mac, "voters", dict(v)):
            raise IntegrityError("voter row MAC invalid")
        now = get_clock().now_dt()
        prev = ctx.conn.execute("SELECT * FROM auth_codes WHERE election_id = ? AND voter_id = ? "
                                "AND method = 'email_otp'", (election_id, voter_id)).fetchone()
        if prev is not None and _parse(prev["expires_at"]) - OTP_TTL + OTP_RESEND_AFTER > now:
            return  # çok sık istek: sessizce yok say
        code = "".join(secrets.choice("0123456789") for _ in range(8))
        fields = {"code_hash": _ph.hash(code), "expires_at": _ts(now + OTP_TTL),
                  "attempts": 0, "used": 0}
        if prev is None:
            insert_row(ctx.conn, ctx.keys.row_mac, "auth_codes",
                       {"election_id": election_id, "voter_id": voter_id,
                        "method": "email_otp", **fields})
        else:
            update_row(ctx.conn, ctx.keys.row_mac, "auth_codes",
                       {"election_id": election_id, "voter_id": voter_id, "method": "email_otp"},
                       fields)
        title = e["title"]
    mailer.send(ctx.settings, email, f"Oy verme kodunuz: {title}",
                f"Merhaba,\n\n'{title}' oylaması için giriş kodunuz: {code}\n\n"
                f"Kod 10 dakika geçerlidir ve yalnızca bir kez kullanılabilir.\n"
                f"Bu isteği siz yapmadıysanız seçim yöneticisine bildirin.\n")


def verify_code(ctx: Context, election_id: str, voter_id: str, method: str, code: str) -> bool:
    if method not in ("printed_code", "email_otp"):
        raise VoterAuthError("unknown method")
    with transaction(ctx.conn):
        e = get_election(ctx, election_id)
        _allowed(e, method)
        row = ctx.conn.execute("SELECT * FROM auth_codes WHERE election_id = ? AND voter_id = ? "
                               "AND method = ?", (election_id, voter_id, method)).fetchone()
        if row is None:
            _check(_DUMMY_HASH, code)  # bilinmeyen seçmende de aynı süre harcansın
            return False
        row = dict(row)
        if not rowmac.verify(ctx.keys.row_mac, "auth_codes", row):
            raise IntegrityError("auth code row MAC invalid")
        pk = {"election_id": election_id, "voter_id": voter_id, "method": method}
        expired = row["expires_at"] is not None and _parse(row["expires_at"]) < get_clock().now_dt()
        if row["used"] or expired or row["attempts"] >= MAX_ATTEMPTS:
            _check(_DUMMY_HASH, code)
            return False
        candidate = _normalize(code) if method == "printed_code" else code.strip()
        if not _check(row["code_hash"], candidate):
            update_row(ctx.conn, ctx.keys.row_mac, "auth_codes", pk,
                       {"attempts": row["attempts"] + 1})
            return False
        if method == "email_otp":
            update_row(ctx.conn, ctx.keys.row_mac, "auth_codes", pk, {"used": 1})
        chain.record_voter_event(ctx.conn, ctx.keys, election_id, voter_id,
                                 "voter_login", {"method": method})
        return True


def _check(code_hash: str, code: str) -> bool:
    try:
        return _ph.verify(code_hash, code)
    except VerificationError:
        return False
