"""Seçim yaşam döngüsü: oluşturma, yapılandırma, açma (mühürleme), kapama ve sayım.

Açma ve kapama doğrudan çağrılmaz; governance.py üzerinden iki kişi onayıyla uygulanır.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..audit import chain, checkpoint
from ..context import Context
from ..crypto import blind_rsa, fieldenc, keystore, rowmac
from ..db.connection import IntegrityError, insert_row, transaction, update_row
from ..timekeeping import ClockError, get_clock, parse_iso
from . import ballot_types
from . import config as econfig
from .ballot_types import ConfigError


class ElectionStateError(RuntimeError):
    pass


def get_election(ctx: Context, election_id: str) -> dict[str, Any]:
    row = ctx.conn.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
    if row is None:
        raise LookupError(f"election not found: {election_id}")
    row = dict(row)
    if not rowmac.verify(ctx.keys.row_mac, "elections", row):
        raise IntegrityError(f"election {election_id}: row MAC invalid")
    return row


def window(e: dict[str, Any], now: float | None = None) -> str:
    """Oylamanın zaman penceresindeki yeri: 'before' | 'during' | 'after'."""
    cfg = json.loads(e["config"])
    now = get_clock().now() if now is None else now
    if cfg.get("opens_at") and now < parse_iso(cfg["opens_at"]).timestamp():
        return "before"
    if now >= parse_iso(cfg["closes_at"]).timestamp():
        return "after"
    return "during"


def require_voting_window(e: dict[str, Any]) -> None:
    """Oy hakkı/oy kabulü için: oylama açık, saat sağlam ve pencere içinde olmalı."""
    if e["status"] != "open":
        raise ElectionStateError("election is not open")
    get_clock().require_sane()
    w = window(e)
    if w == "before":
        raise ElectionStateError("voting has not started yet")
    if w == "after":
        raise ElectionStateError("voting period has ended")


def roll_hash(voter_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(voter_ids)).encode()).hexdigest()


def create_election(ctx: Context, admin_id: str, election_id: str, title: str,
                    ballot_type: str, cfg: dict[str, Any]) -> None:
    normalized = econfig.normalize(ballot_type, cfg)
    with transaction(ctx.conn):
        chain.record(ctx.conn, ctx.keys, admin_id, "election_create",
                     {"election_id": election_id, "title": title, "ballot_type": ballot_type,
                      "config": normalized})
        insert_row(ctx.conn, ctx.keys.row_mac, "elections", {
            "id": election_id, "title": title, "ballot_type": ballot_type,
            "config": econfig.canonical(normalized), "config_hash": None, "status": "draft",
            "roll_hash": None, "pubkey_pem": None, "privkey_wrapped": None, "result": None,
            "created_by": admin_id})
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)


def update_election(ctx: Context, admin_id: str, election_id: str, *, title: str | None = None,
                    ballot_type: str | None = None, cfg: dict[str, Any] | None = None) -> None:
    with transaction(ctx.conn):
        e = get_election(ctx, election_id)
        if e["status"] != "draft":
            raise ElectionStateError("only draft elections can be reconfigured")
        bt = ballot_type or e["ballot_type"]
        normalized = econfig.normalize(bt, cfg if cfg is not None else json.loads(e["config"]))
        changes = {"title": title or e["title"], "ballot_type": bt,
                   "config": econfig.canonical(normalized)}
        chain.record(ctx.conn, ctx.keys, admin_id, "election_update",
                     {"election_id": election_id, **changes})
        update_row(ctx.conn, ctx.keys.row_mac, "elections", {"id": election_id}, changes)
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)


def apply_open(ctx: Context, election_id: str) -> None:
    """İşlem İÇİNDE, governance tarafından çağrılır. Yapılandırma ve listeyi mühürler."""
    e = get_election(ctx, election_id)
    if e["status"] != "draft":
        raise ElectionStateError("election is not in draft")
    cfg = json.loads(e["config"])
    econfig.normalize(e["ballot_type"], cfg)  # şemaya hâlâ uygun mu?
    roll = [r["voter_id"] for r in ctx.conn.execute(
        "SELECT ev.voter_id, v.status FROM election_voters ev JOIN voters v ON v.id = ev.voter_id "
        "WHERE ev.election_id = ?", (election_id,)) if r["status"] == "active"]
    total = ctx.conn.execute("SELECT COUNT(*) FROM election_voters WHERE election_id = ?",
                             (election_id,)).fetchone()[0]
    if len(roll) != total:
        raise ElectionStateError("voter roll contains disabled voters")
    if len(roll) < cfg["min_turnout"]:
        raise ConfigError("voter roll is smaller than min_turnout; results could never be shown")
    get_clock().require_sane()
    if window(e) == "after":
        raise ConfigError("closes_at is already in the past; update the schedule first")

    sk = blind_rsa.generate_key(ctx.settings.rsa_bits)
    update_row(ctx.conn, ctx.keys.row_mac, "elections", {"id": election_id}, {
        "config_hash": econfig.config_hash(e["ballot_type"], cfg),
        "roll_hash": roll_hash(roll),
        "pubkey_pem": keystore.public_pem(sk),
        "privkey_wrapped": keystore.wrap_private_key(ctx.keys.wrap, election_id, sk),
        "status": "open",
    })


def apply_close(ctx: Context, election_id: str) -> dict[str, Any]:
    """İşlem İÇİNDE çağrılır: sandığı kapatır, özel anahtarı imha eder ve sayar."""
    e = get_election(ctx, election_id)
    if e["status"] != "open":
        raise ElectionStateError("election is not open")
    # Planlanan bitişten önce kapanış YOK: aksi halde yöneticiler sandığı erken açıp
    # katılımı/sonucu görebilirdi. Saat dış kaynaklarla doğrulanmış olmalı.
    clock = get_clock()
    clock.require_trusted()
    if window(e) != "after":
        raise ElectionStateError(
            f"election cannot be closed before its scheduled end "
            f"({json.loads(e['config'])['closes_at']}); results stay sealed until then")
    # Seçmen olay zincirinin başını ana zincire mühürle: bundan sonra bu zincirden kayıt
    # silinmesi/eklenmesi ana zincirle çelişir. Sayı artık gizli değil (sonuçla yayımlanıyor).
    entries, head = chain.voter_log_head(ctx.conn, election_id)
    chain.record(ctx.conn, ctx.keys, "system", "voter_log_sealed",
                 {"election_id": election_id, "entries": entries, "head": head})
    # Anahtar imhası: bu andan sonra kimse (yönetici dahil) geçerli yeni oy üretemez.
    update_row(ctx.conn, ctx.keys.row_mac, "elections", {"id": election_id},
               {"status": "closed", "privkey_wrapped": None})
    result = tally(ctx, election_id)
    update_row(ctx.conn, ctx.keys.row_mac, "elections", {"id": election_id},
               {"status": "tallied", "result": json.dumps(result, ensure_ascii=False,
                                                          sort_keys=True)})
    return result


def tally(ctx: Context, election_id: str) -> dict[str, Any]:
    e = get_election(ctx, election_id)
    cfg = json.loads(e["config"])
    bt = ballot_types.get(e["ballot_type"])
    pk = keystore.load_public_pem(e["pubkey_pem"])
    valid, rejected = [], 0
    for r in ctx.conn.execute("SELECT token_hash, token, sig, ballot FROM ballots "
                              "WHERE election_id = ?", (election_id,)):
        # Sandıktaki her oy yeniden doğrulanır: DB'ye doğrudan eklenmiş sahte oylar sayılmaz.
        ok = (hashlib.sha256(r["token"]).digest() == r["token_hash"]
              and blind_rsa.verify(pk, r["token"], r["sig"]))
        try:
            ballot = json.loads(fieldenc.decrypt(
                ctx.keys.field, f"ballots.ballot/{election_id}/{r['token_hash'].hex()}",
                r["ballot"]))
            bt.validate(ballot, cfg["ballot"])
        except (ValueError, ballot_types.InvalidBallot, fieldenc.FieldDecryptError):
            ok = False  # sahte, değiştirilmiş ya da başka satırdan taşınmış pusula
        if ok:
            valid.append(ballot)
        else:
            rejected += 1
    eligible = ctx.conn.execute("SELECT COUNT(*) FROM election_voters WHERE election_id = ?",
                                (election_id,)).fetchone()[0]
    issued = ctx.conn.execute("SELECT COUNT(*) FROM credential_issuance WHERE election_id = ?",
                              (election_id,)).fetchone()[0]
    clock = get_clock()
    result: dict[str, Any] = {"eligible": eligible, "credentials_issued": issued,
                              "turnout": len(valid), "rejected_ballots": rejected,
                              "tallied_at": clock.iso(), "time_assurance": clock.assurance}
    if len(valid) < cfg["min_turnout"]:
        # Çok az oyda döküm, kimin neye oy verdiğini tahmin ettirebilir → gizlenir.
        result["withheld"] = True
    else:
        result["withheld"] = False
        result["tally"] = bt.tally(valid, cfg["ballot"])
    return result


def bulletin(ctx: Context, election_id: str) -> dict[str, Any]:
    """Kapanış sonrası yayımlanan ilan panosu.

    Makbuz listesi ve oy içerikleri AYRI ve bağımsız sıralanmış iki liste olarak yayımlanır:
    seçmen oyunun sayıldığını doğrulayabilir ama içeriğini kimseye ispatlayamaz.
    """
    e = get_election(ctx, election_id)
    if e["status"] not in ("tallied", "archived"):
        raise ElectionStateError("bulletin is published only after tallying")
    result = json.loads(e["result"])
    receipts = sorted(r[0].hex() for r in ctx.conn.execute(
        "SELECT token_hash FROM ballots WHERE election_id = ?", (election_id,)))
    out = {"election_id": e["id"], "title": e["title"], "ballot_type": e["ballot_type"],
           "config": json.loads(e["config"]), "config_hash": e["config_hash"],
           "roll_hash": e["roll_hash"], "public_key_pem": e["pubkey_pem"].decode(),
           "receipts": receipts, "result": result}
    if not result["withheld"]:
        plain = []
        for r in ctx.conn.execute("SELECT token_hash, ballot FROM ballots WHERE election_id = ?",
                                  (election_id,)):
            try:
                plain.append(fieldenc.decrypt(
                    ctx.keys.field, f"ballots.ballot/{election_id}/{r[0].hex()}", r[1]))
            except fieldenc.FieldDecryptError:
                continue  # sayıma da alınmadı (rejected_ballots)
        out["ballots"] = sorted(plain)
    return out


def close_due_elections(ctx: Context) -> list[str]:
    """Bitiş zamanı gelmiş açık oylamaları otomatik kapatır ve sayar (zamanlayıcı/cron).

    Zamanlanmış kapanış için ayrıca onay gerekmez: bitiş anı oylama açılırken iki yönetici
    onayıyla mühürlenmişti. Saat doğrulanamıyorsa hiçbir şey yapılmaz (sonra tekrar denenir).
    """
    clock = get_clock()
    try:
        clock.require_trusted()
    except ClockError:
        return []
    closed = []
    for (eid,) in ctx.conn.execute("SELECT id FROM elections WHERE status = 'open'").fetchall():
        try:
            with transaction(ctx.conn):
                e = get_election(ctx, eid)
                if e["status"] != "open" or window(e) != "after":
                    continue
                chain.record(ctx.conn, ctx.keys, "system", "election_auto_close",
                             {"election_id": eid, "assurance": clock.assurance})
                apply_close(ctx, eid)
        except (ElectionStateError, ClockError):
            continue
        finish_close(ctx)
        closed.append(eid)
    return closed


def finish_close(ctx: Context) -> None:
    """Kapanış sonrası: imha edilen anahtar sayfalarını dosyadan at, checkpoint al.

    Windows'ta başka bir bağlantı dosyayı okurken VACUUM kilitlenebilir; kapanış zaten
    tamamlanmıştır (secure_delete silinen sayfaları sıfırladı), bu yüzden birkaç deneme yapılır
    ve başarısızlık kapanışı bozmaz.
    """
    import sqlite3
    import time
    for attempt in range(5):
        try:
            ctx.conn.execute("VACUUM")
            break
        except sqlite3.OperationalError:
            time.sleep(0.5 * (attempt + 1))
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
