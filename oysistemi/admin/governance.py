"""İki kişi kuralı (maker–checker): kritik değişiklikler öneri + bağımsız onayla uygulanır.

Seçmen ekleme/devre dışı bırakma, seçmen listesine ekleme/çıkarma, yeni yönetici ekleme,
seçimi açma ve kapama doğrudan yapılamaz. Bir yönetici önerir, öneren DIŞINDAKİ yöneticiler
onaylar. Gereken onay sayısına ulaşılınca değişiklik aynı işlem (transaction) içinde uygulanır.
Herhangi bir ret öneriyi düşürür.
"""
from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from typing import Any

from argon2 import PasswordHasher

from ..audit import chain, checkpoint
from ..context import Context
from ..crypto import fieldenc, rowmac
from ..db.connection import IntegrityError, insert_row, transaction, update_row
from ..elections import service as elections
from . import enrollment

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_ph = PasswordHasher()


class GovernanceError(RuntimeError):
    pass


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise GovernanceError(f"invalid {what}: {value!r}")
    return value


def require_admin(ctx: Context, admin_id: str) -> dict[str, Any]:
    row = ctx.conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if row is None:
        raise GovernanceError("unknown admin")
    row = dict(row)
    if not rowmac.verify(ctx.keys.row_mac, "admins", row):
        raise IntegrityError(f"admin {admin_id}: row MAC invalid")
    if row["role"] != "admin":
        raise GovernanceError("auditors cannot change data")
    return row


# ───────────────────────── Uygulayıcılar (işlem içinde çalışır) ─────────────────────────

def _voter_add(ctx: Context, p: dict[str, Any]) -> None:
    vid = p["id"]
    insert_row(ctx.conn, ctx.keys.row_mac, "voters", {
        "id": vid,
        "display_name": fieldenc.encrypt(ctx.keys.field, f"voters.display_name/{vid}",
                                         p["display_name"]),
        "email": fieldenc.encrypt(ctx.keys.field, f"voters.email/{vid}", p.get("email")),
        "status": "active", "created_at": chain.now()})


def voter_plain(ctx: Context, row: Any) -> dict[str, Any]:
    """Seçmen satırının şifreli alanlarını çözülmüş olarak döndürür."""
    d = dict(row)
    for f in ("display_name", "email"):
        if f in d:
            d[f] = fieldenc.decrypt(ctx.keys.field, f"voters.{f}/{d['id']}", d[f])
    return d


def request_payload(ctx: Context, req: Any) -> dict[str, Any]:
    return json.loads(fieldenc.decrypt(ctx.keys.field, f"change_requests.payload/{req['id']}",
                                       req["payload"]))


def _voters_add(ctx: Context, p: dict[str, Any]) -> None:
    for v in p["voters"]:
        _voter_add(ctx, v)


def _voter_disable(ctx: Context, p: dict[str, Any]) -> None:
    update_row(ctx.conn, ctx.keys.row_mac, "voters", {"id": p["id"]}, {"status": "disabled"})


def _roll_add(ctx: Context, p: dict[str, Any]) -> None:
    for vid in p["voter_ids"]:
        v = ctx.conn.execute("SELECT * FROM voters WHERE id = ?", (vid,)).fetchone()
        if v is None or not rowmac.verify(ctx.keys.row_mac, "voters", dict(v)):
            raise GovernanceError(f"voter {vid} missing or tampered")
        if v["status"] != "active":
            raise GovernanceError(f"voter {vid} is disabled")
        insert_row(ctx.conn, ctx.keys.row_mac, "election_voters",
                   {"election_id": p["election_id"], "voter_id": vid})


def _roll_remove(ctx: Context, p: dict[str, Any]) -> None:
    for vid in p["voter_ids"]:
        cur = ctx.conn.execute("DELETE FROM election_voters WHERE election_id = ? AND voter_id = ?",
                               (p["election_id"], vid))
        if cur.rowcount != 1:
            raise GovernanceError(f"voter {vid} is not on the roll")


def _insert_admin(ctx: Context, admin_id: str, username: str, pw_hash: str,
                  role: str = "admin") -> None:
    insert_row(ctx.conn, ctx.keys.row_mac, "admins", {
        "id": admin_id, "username": username, "pw_hash": pw_hash,
        # TOTP ilk girişte kaydedilir; None "parola" değil (bandit yanlış pozitif)
        "totp_secret_enc": None,  # nosec B105
        "role": role, "created_at": chain.now()})


def _admin_add(ctx: Context, p: dict[str, Any]) -> None:
    """Hesap parolasız oluşturulur; B parçası yalnızca onaylayana döner (bkz. enrollment.py)."""
    part_b = enrollment.new_part()
    _insert_admin(ctx, p["id"], p["username"],
                  enrollment.pending_marker(p["enroll_a_hash"], enrollment.hash_part(part_b)),
                  p.get("role", "admin"))
    ctx.outputs["enroll_b"] = {"username": p["username"], "part": part_b}


def _election_open(ctx: Context, p: dict[str, Any]) -> None:
    elections.apply_open(ctx, p["election_id"], p)


def _election_close(ctx: Context, p: dict[str, Any]) -> None:
    elections.apply_close(ctx, p["election_id"])


def _validate(kind: str, p: dict[str, Any]) -> dict[str, Any]:
    if kind in ("voter_add", "voter_disable"):
        _check_id(p.get("id"), "voter id")
        if kind == "voter_add":
            _check_voter(p)
    elif kind == "voters_add":
        voters = p.get("voters")
        if not isinstance(voters, list) or not voters:
            raise GovernanceError("voters must be a non-empty list")
        ids = [_check_id(v.get("id") if isinstance(v, dict) else None, "voter id") for v in voters]
        if len(set(ids)) != len(ids):
            raise GovernanceError("duplicate voter ids in batch")
        for v in voters:
            _check_voter(v)
    elif kind in ("roll_add", "roll_remove"):
        _check_id(p.get("election_id"), "election id")
        ids = p.get("voter_ids")
        if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids):
            raise GovernanceError("voter_ids must be a non-empty list without duplicates")
        for v in ids:
            _check_id(v, "voter id")
    elif kind == "admin_add":
        # Öneren yeni hesabın kimlik bilgisini BELİRLEYEMEZ (parola, TOTP): yalnızca kayıt
        # belirtecinin A parçasının özeti kabul edilir.
        if set(p) - {"id", "username", "role", "enroll_a_hash"}:
            raise GovernanceError("admin_add accepts only id, username, role, enroll_a_hash; "
                                  "credentials are set by the new admin")
        _check_id(p.get("id"), "admin id")
        _check_id(p.get("username"), "username")
        if p.get("role", "admin") not in ("admin", "auditor"):
            raise GovernanceError("invalid role")
        if not str(p.get("enroll_a_hash", "")).startswith("$argon2"):
            raise GovernanceError("enroll_a_hash must be an argon2 hash")
    elif kind in ("election_open", "election_close"):
        _check_id(p.get("election_id"), "election id")
    return p


def _check_voter(v: dict[str, Any]) -> None:
    if set(v) - {"id", "display_name", "email"}:
        raise GovernanceError("unexpected voter fields")
    if not str(v.get("display_name", "")).strip() or len(v["display_name"]) > 200:
        raise GovernanceError("display_name required (max 200 chars)")
    email = v.get("email")
    if email is not None and not _EMAIL_RE.match(email):
        raise GovernanceError(f"invalid email: {email!r}")


HANDLERS: dict[str, Callable[[Context, dict[str, Any]], None]] = {
    "voter_add": _voter_add,
    "voters_add": _voters_add,
    "voter_disable": _voter_disable,
    "roll_add": _roll_add,
    "roll_remove": _roll_remove,
    "admin_add": _admin_add,
    "election_open": _election_open,
    "election_close": _election_close,
}


# ───────────────────────── Genel API ─────────────────────────

def hash_password(password: str) -> str:
    return _ph.hash(password)


def propose(ctx: Context, admin_id: str, kind: str, payload: dict[str, Any]) -> str:
    if kind not in HANDLERS:
        raise GovernanceError(f"unknown change kind: {kind}")
    _validate(kind, payload)
    if kind == "election_open":
        # Onay belirli bir içeriğe bağlanır; bağlamayı istemci değil sunucu hesaplar.
        payload = {"election_id": payload["election_id"],
                   **elections.open_binding(ctx, payload["election_id"])}
    request_id = secrets.token_hex(8)
    with transaction(ctx.conn):
        require_admin(ctx, admin_id)
        required = ctx.settings.default_required_approvals
        chain.record(ctx.conn, ctx.keys, admin_id, "change_proposed",
                     {"request_id": request_id, "kind": kind, "payload": payload,
                      "required_approvals": required})
        insert_row(ctx.conn, ctx.keys.row_mac, "change_requests", {
            "id": request_id, "kind": kind,
            "payload": fieldenc.encrypt(ctx.keys.field, f"change_requests.payload/{request_id}",
                                        json.dumps(payload, sort_keys=True, ensure_ascii=False)),
            "proposed_by": admin_id, "status": "pending", "required_approvals": required,
            "created_at": chain.now()})
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
    return request_id


def decide(ctx: Context, admin_id: str, request_id: str, decision: str) -> str:
    """Onay/ret kaydeder. Dönüş: isteğin yeni durumu ('pending' | 'applied' | 'rejected')."""
    if decision not in ("approve", "reject"):
        raise GovernanceError("decision must be 'approve' or 'reject'")
    with transaction(ctx.conn):
        require_admin(ctx, admin_id)
        req = ctx.conn.execute("SELECT * FROM change_requests WHERE id = ?",
                               (request_id,)).fetchone()
        if req is None:
            raise GovernanceError("unknown request")
        req = dict(req)
        if not rowmac.verify(ctx.keys.row_mac, "change_requests", req):
            raise IntegrityError(f"change request {request_id}: row MAC invalid")
        if req["status"] != "pending":
            raise GovernanceError(f"request already {req['status']}")
        if req["proposed_by"] == admin_id:
            raise GovernanceError("the proposer cannot approve or reject their own request")
        if ctx.conn.execute("SELECT 1 FROM approvals WHERE request_id = ? AND admin_id = ?",
                            (request_id, admin_id)).fetchone():
            raise GovernanceError("admin already decided on this request")

        chain.record(ctx.conn, ctx.keys, admin_id, f"change_{decision}d",
                     {"request_id": request_id, "kind": req["kind"]})
        ctx.conn.execute("INSERT INTO approvals (request_id, admin_id, decision, ts) "
                         "VALUES (?, ?, ?, ?)", (request_id, admin_id, decision, chain.now()))

        new_status = "pending"
        if decision == "reject":
            new_status = "rejected"
        else:
            approved = ctx.conn.execute(
                "SELECT COUNT(*) FROM approvals WHERE request_id = ? AND decision = 'approve'",
                (request_id,)).fetchone()[0]
            if approved >= req["required_approvals"]:
                payload = request_payload(ctx, req)
                chain.record(ctx.conn, ctx.keys, "system", "change_applied",
                             {"request_id": request_id, "kind": req["kind"],
                              "payload": payload})
                HANDLERS[req["kind"]](ctx, payload)
                new_status = "applied"
        if new_status != "pending":
            update_row(ctx.conn, ctx.keys.row_mac, "change_requests", {"id": request_id},
                       {"status": new_status})
    if new_status == "applied" and req["kind"] == "election_close":
        elections.finish_close(ctx)
    else:
        checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
    return new_status


def bootstrap_admins(ctx: Context, admins: list[tuple[str, str, str]]) -> None:
    """İlk kurulum: yalnızca hiç yönetici yokken, en az iki yönetici birlikte oluşturulur.

    Tek yöneticiyle başlamak iki kişi kuralını anlamsız kılardı.
    """
    if len(admins) < 2:
        raise GovernanceError("bootstrap requires at least two admins")
    with transaction(ctx.conn):
        if ctx.conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]:
            raise GovernanceError("admins already exist; use an admin_add change request")
        chain.record(ctx.conn, ctx.keys, "bootstrap", "admins_bootstrap",
                     {"admins": [{"id": a[0], "username": a[1]} for a in admins]})
        for admin_id, username, password in admins:
            _check_id(admin_id, "admin id")
            _check_id(username, "username")
            _insert_admin(ctx, admin_id, username, hash_password(password))
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
