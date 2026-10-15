"""Checkpoint'ler: DB durumunun HMAC'li anlık özeti, DB DIŞINA da yazılır.

Satır MAC'i bir satırın *eklenmesini/değiştirilmesini* yakalar ama *silinmesini* yakalayamaz
(silinen satırın kontrol edilecek MAC'i yoktur). Checkpoint tablo özetlerini ve sayımlarını
saklar. Son checkpoint'ten sonra meşru bir değişiklik yoksa, mevcut durum checkpoint ile
birebir aynı olmalıdır. Tek bir satırın kaybolması bile özeti değiştirir.

Harici dosya salt-ekleme (append-only) kullanılır. Üretimde bu dosya ayrı bir diske,
WORM depolamaya veya e-posta/çıktı ile kurum dışına kopyalanmalıdır.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from typing import Any

from ..crypto import rowmac
from ..db.connection import transaction
from .chain import now

# auth_codes bilinçli olarak dışarıda: deneme sayaçları her girişte değişir (denetim kaydı
# olmadan), checkpoint'le karşılaştırılırsa sürekli yanlış alarm üretir. Satır MAC'leri
# yine de doğrulanır.
TRACKED_TABLES = ("voters", "admins", "elections", "election_voters", "change_requests")


def table_digest(conn: sqlite3.Connection, table: str) -> tuple[str, int]:
    if table not in rowmac.MAC_FIELDS:
        raise ValueError(table)
    hashes_ = sorted(hashlib.sha256(rowmac.canonical_row(table, dict(r))).hexdigest()
                     for r in conn.execute(f"SELECT * FROM {table}"))
    return hashlib.sha256("\n".join(hashes_).encode()).hexdigest(), len(hashes_)


def snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    head = conn.execute(
        "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    tables = {}
    for t in TRACKED_TABLES:
        digest, count = table_digest(conn, t)
        tables[t] = {"digest": digest, "count": count}
    return {"audit_seq": head["seq"] if head else 0,
            "audit_head": head["entry_hash"] if head else None,
            "tables": tables}


def _mac(key: bytes, body: str) -> str:
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def take(conn: sqlite3.Connection, key: bytes, external_path: Path) -> dict[str, Any]:
    with transaction(conn):
        snap = snapshot(conn)
        snap["ts"] = now()
        body = json.dumps(snap, sort_keys=True, separators=(",", ":"))
        mac = _mac(key, body)
        conn.execute("INSERT INTO checkpoints (audit_seq, body, mac) VALUES (?, ?, ?)",
                     (snap["audit_seq"], body, mac))
    external_path.parent.mkdir(parents=True, exist_ok=True)
    with open(external_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"body": body, "mac": mac}) + "\n")
    return snap


def load_external(key: bytes, external_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Harici checkpoint'leri okur; MAC'i geçersiz olan satırları raporlar."""
    if not external_path.exists():
        return [], []
    good, problems = [], []
    for i, line in enumerate(external_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            rec = json.loads(line)
            if not hmac.compare_digest(_mac(key, rec["body"]), rec["mac"]):
                problems.append(f"external checkpoint line {i}: MAC invalid")
                continue
            good.append(json.loads(rec["body"]))
        except (ValueError, KeyError):
            problems.append(f"external checkpoint line {i}: unreadable")
    return good, problems


def compare(conn: sqlite3.Connection, key: bytes, external_path: Path) -> list[tuple[str, str]]:
    """(seviye, mesaj) listesi döner. Seviye: 'critical' | 'warning'."""
    findings: list[tuple[str, str]] = []
    cps, problems = load_external(key, external_path)
    findings += [("critical", p) for p in problems]
    if not cps:
        findings.append(("warning", "no external checkpoint found"))
        return findings

    # Her checkpoint'in işaret ettiği denetim kaydı hâlâ aynı olmalı (geçmiş yeniden yazılmamış).
    for cp in cps:
        if cp["audit_seq"] == 0:
            continue
        row = conn.execute("SELECT entry_hash FROM audit_log WHERE seq = ?",
                           (cp["audit_seq"],)).fetchone()
        if row is None:
            findings.append(("critical", f"audit entry {cp['audit_seq']} referenced by a "
                                         "checkpoint is missing (log truncated)"))
        elif row["entry_hash"] != cp["audit_head"]:
            findings.append(("critical", f"audit entry {cp['audit_seq']} differs from "
                                         "checkpoint (history rewritten)"))

    last = cps[-1]
    current = snapshot(conn)
    if current["audit_seq"] < last["audit_seq"]:
        findings.append(("critical", "audit log is shorter than the last checkpoint"))
    elif current["audit_seq"] > last["audit_seq"]:
        findings.append(("warning", f"{current['audit_seq'] - last['audit_seq']} audit entries "
                                    "after the last checkpoint; table state not comparable"))
    else:
        for t, info in last["tables"].items():
            cur = current["tables"].get(t)
            if cur is None:
                continue
            if cur["count"] != info["count"]:
                findings.append(("critical", f"{t}: row count {cur['count']} != checkpoint "
                                             f"{info['count']} (rows added/removed out of band)"))
            elif cur["digest"] != info["digest"]:
                findings.append(("critical", f"{t}: content differs from checkpoint"))
    return findings
