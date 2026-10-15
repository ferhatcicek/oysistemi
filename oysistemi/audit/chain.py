"""Hash zincirli, HMAC'li denetim kaydı (ayak izi).

entry_hash(n) = SHA256(prev_hash || kanonik(seq, ts, actor, action, payload))
entry_mac(n)  = HMAC(K_audit, entry_hash(n))

Bir kaydın silinmesi, değiştirilmesi ya da araya kayıt eklenmesi zinciri kırar.
MAC, anahtarı bilmeyen birinin zinciri baştan "yeniden hesaplamasını" engeller.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from ..crypto import fieldenc
from ..timekeeping import ClockError, get_clock, parse_iso

GENESIS = "0" * 64


def now() -> str:
    """Tüm sistemde tek zaman kaynağı: güvenilir saat (sistem saati DEĞİL)."""
    return get_clock().iso()


def check_high_water(conn: sqlite3.Connection) -> None:
    """Saat, denetim zincirindeki son kaydın gerisindeyse geri alma vardır.

    Zincir HMAC'li olduğu için son zaman damgası sahte biçimde geriye çekilemez; bu yüzden
    sistemin "en az bu ana kadar yaşandığının" kanıtıdır.
    """
    last = conn.execute("SELECT MAX(ts) AS ts FROM (SELECT MAX(ts) AS ts FROM audit_log "
                        "UNION ALL SELECT MAX(ts) FROM voter_log)").fetchone()
    if last is None or last["ts"] is None:
        return
    clock = get_clock()
    behind = parse_iso(last["ts"]).timestamp() - clock.now()
    if behind > clock.tolerance:
        clock.mark_tampered(f"clock is {behind:.0f}s behind the last log entry ({last['ts']})")
        raise ClockError("clock rollback detected: time is earlier than the audit log")


def _canon(seq: int, ts: str, actor: str, action: str, payload: str) -> bytes:
    return json.dumps([seq, ts, actor, action, payload],
                      separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(prev_hash: str, seq: int, ts: str, actor: str, action: str, payload: str) -> str:
    return hashlib.sha256(prev_hash.encode() + _canon(seq, ts, actor, action, payload)).hexdigest()


def entry_mac(key: bytes, e_hash: str) -> str:
    return hmac.new(key, e_hash.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    entry_hash: str


def audit_aad(seq: int) -> str:
    return f"audit_log.payload/{seq}"


def voter_aad(election_id: str, seq: int) -> str:
    return f"voter_log.payload/{election_id}/{seq}"


def read_payload(keys: Any, row: Any) -> dict[str, Any]:
    """Denetim veya seçmen kaydının şifreli yükünü çözer."""
    if "election_id" in row.keys():
        aad = voter_aad(row["election_id"], row["seq"])
    else:
        aad = audit_aad(row["seq"])
    return json.loads(fieldenc.decrypt(keys.field, aad, row["payload"]))


def record(conn: sqlite3.Connection, keys: Any, actor: str, action: str,
           payload: dict[str, Any]) -> AuditEntry:
    """Bir işlem içinde (transaction) çağrılmalıdır.

    Kaydı ekler ve _ctx.audit_seq'i bu kayda ayarlar; aynı işlemdeki tablo değişiklikleri
    gölge logda bu sıra numarasıyla görünür.
    """
    if not conn.in_transaction:
        raise RuntimeError("audit.record must run inside a transaction")
    check_high_water(conn)
    last = conn.execute("SELECT seq, entry_hash, ts FROM audit_log ORDER BY seq DESC LIMIT 1"
                        ).fetchone()
    seq, prev = (last["seq"] + 1, last["entry_hash"]) if last else (1, GENESIS)
    # Tolerans içindeki küçük geri sapmalarda bile zincir zamanı geriye gitmez.
    ts = max(now(), last["ts"]) if last else now()
    # Yük şifreli saklanır (ad/e-posta içerebilir); zincir şifreli metin üzerinden kurulur,
    # bu yüzden bütünlük doğrulaması için şifre çözmek gerekmez.
    body = fieldenc.encrypt(keys.field, audit_aad(seq), json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    h = entry_hash(prev, seq, ts, actor, action, body)
    conn.execute(
        "INSERT INTO audit_log (seq, ts, actor, action, payload, prev_hash, entry_hash, entry_mac)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, ts, actor, action, body, prev, h, entry_mac(keys.audit, h)))
    conn.execute("UPDATE _ctx SET audit_seq = ? WHERE id = 1", (seq,))
    return AuditEntry(seq, h)


def verify_chain(conn: sqlite3.Connection, key: bytes) -> list[str]:
    """Zinciri baştan sona doğrular; bulunan sorunları döndürür."""
    problems: list[str] = []
    prev, expected_seq, prev_ts = GENESIS, 1, ""
    for r in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        if r["ts"] < prev_ts:
            problems.append(f"audit seq {r['seq']}: timestamp goes backwards ({r['ts']} < "
                            f"{prev_ts}) — clock manipulation or backdated entry")
        prev_ts = max(prev_ts, r["ts"])
        if r["seq"] != expected_seq:
            problems.append(f"audit seq gap: expected {expected_seq}, found {r['seq']}")
        if r["prev_hash"] != prev:
            problems.append(f"audit seq {r['seq']}: prev_hash does not link to previous entry")
        h = entry_hash(r["prev_hash"], r["seq"], r["ts"], r["actor"], r["action"], r["payload"])
        if h != r["entry_hash"]:
            problems.append(f"audit seq {r['seq']}: content altered (hash mismatch)")
        if not hmac.compare_digest(entry_mac(key, r["entry_hash"]), r["entry_mac"]):
            problems.append(f"audit seq {r['seq']}: MAC invalid (forged entry)")
        prev, expected_seq = r["entry_hash"], r["seq"] + 1
    return problems


# ───────────────────────── Seçmen olay zinciri (oylama başına) ─────────────────────────

def record_voter_event(conn: sqlite3.Connection, keys: Any, election_id: str, voter_id: str,
                       action: str, payload: dict[str, Any]) -> None:
    """Seçmen olayını oylamanın kendi zincirine yazar (ana zincirin sırasını etkilemez)."""
    if not conn.in_transaction:
        raise RuntimeError("record_voter_event must run inside a transaction")
    check_high_water(conn)
    last = conn.execute("SELECT seq, entry_hash, ts FROM voter_log WHERE election_id = ? "
                        "ORDER BY seq DESC LIMIT 1", (election_id,)).fetchone()
    seq, prev = (last["seq"] + 1, last["entry_hash"]) if last else (1, GENESIS)
    ts = max(now(), last["ts"]) if last else now()
    body = fieldenc.encrypt(keys.field, voter_aad(election_id, seq), json.dumps(
        {"election_id": election_id, **payload}, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False))
    h = entry_hash(prev, seq, ts, voter_id, action, body)
    conn.execute("INSERT INTO voter_log (election_id, seq, ts, voter_id, action, payload, "
                 "prev_hash, entry_hash, entry_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (election_id, seq, ts, voter_id, action, body, prev, h,
                  entry_mac(keys.audit, h)))


def voter_log_head(conn: sqlite3.Connection, election_id: str) -> tuple[int, str]:
    last = conn.execute("SELECT seq, entry_hash FROM voter_log WHERE election_id = ? "
                        "ORDER BY seq DESC LIMIT 1", (election_id,)).fetchone()
    return (last["seq"], last["entry_hash"]) if last else (0, GENESIS)


def verify_voter_chain(conn: sqlite3.Connection, key: bytes, election_id: str) -> list[str]:
    problems: list[str] = []
    prev, expected_seq, prev_ts = GENESIS, 1, ""
    for r in conn.execute("SELECT * FROM voter_log WHERE election_id = ? ORDER BY seq",
                          (election_id,)):
        where = f"voter log {election_id}"
        if r["seq"] != expected_seq or r["prev_hash"] != prev:
            problems.append(f"{where}: chain broken (entry missing or inserted)")
        if r["ts"] < prev_ts:
            problems.append(f"{where}: timestamp goes backwards")
        h = entry_hash(r["prev_hash"], r["seq"], r["ts"], r["voter_id"], r["action"],
                       r["payload"])
        if h != r["entry_hash"]:
            problems.append(f"{where}: entry content altered")
        if not hmac.compare_digest(entry_mac(key, r["entry_hash"]), r["entry_mac"]):
            problems.append(f"{where}: forged entry (MAC invalid)")
        prev, expected_seq, prev_ts = r["entry_hash"], r["seq"] + 1, max(prev_ts, r["ts"])
    return problems
