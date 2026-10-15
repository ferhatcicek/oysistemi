"""Bütünlük doğrulayıcı: tüm tespit katmanlarını tek raporda birleştirir.

Kontroller:
  1. Şema parmak izi           → tetikleyici silme/değiştirme
  2. Denetim zinciri           → kayıt silme/değiştirme/araya ekleme
  3. Satır MAC'leri            → uygulama dışından ekleme/değiştirme
  4. Gölge log ↔ denetim kaydı → bant dışı değişiklik (sqlite3 CLI vb.)
  5. Harici checkpoint         → satır silme, geçmişin yeniden yazılması
  6. Seçim değişmezleri        → oy sayısı ≤ kimlik bilgisi ≤ seçmen, liste mühürü, imzalar
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ..config import Keys
from ..crypto import blind_rsa, fieldenc, keystore, rowmac
from ..db import connection
from . import chain, checkpoint


@dataclass(frozen=True)
class Finding:
    severity: str  # 'critical' | 'warning'
    code: str
    detail: str


def _rowmac_findings(conn: sqlite3.Connection, keys: Keys) -> list[Finding]:
    out = []
    for table, pk in rowmac.PRIMARY_KEYS.items():
        for r in conn.execute(f"SELECT * FROM {table}"):
            r = dict(r)
            if not rowmac.verify(keys.row_mac, table, r):
                key = "/".join(str(r[k]) for k in pk)
                out.append(Finding("critical", "row_mac",
                                   f"{table} {key}: MAC invalid (inserted or modified outside "
                                   "the application)"))
    return out


def _shadow_findings(conn: sqlite3.Connection) -> list[Finding]:
    out = []
    for r in conn.execute("SELECT * FROM shadow_log WHERE audit_seq IS NULL "
                          "OR audit_seq NOT IN (SELECT seq FROM audit_log) ORDER BY id"):
        out.append(Finding("critical", "out_of_band",
                           f"{r['ts']} {r['op']} on {r['tbl']} ({r['row_key']}) has no matching "
                           "audit entry — changed outside the application"))
    # Gölge log AUTOINCREMENT kullanır; aradaki boşluk satır silindiğini gösterir.
    ids = [r[0] for r in conn.execute("SELECT id FROM shadow_log ORDER BY id")]
    seq_row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'shadow_log'").fetchone()
    expected = list(range(1, (seq_row[0] if seq_row else 0) + 1))
    if ids != expected:
        out.append(Finding("critical", "shadow_gap", "shadow_log has missing rows"))
    return out


def _election_findings(conn: sqlite3.Connection, keys: Keys) -> list[Finding]:
    from ..elections.service import roll_hash

    out = []
    for e in conn.execute("SELECT * FROM elections WHERE status <> 'draft'"):
        eid = e["id"]
        # Oylama sayılmadan önce bulgu mesajları SAYI içermez: katılım bilgisi sızmamalı.
        sealed = e["status"] == "open"

        def n(x: int, sealed: bool = sealed) -> str:
            return "?" if sealed else str(x)

        roll = [r[0] for r in conn.execute(
            "SELECT voter_id FROM election_voters WHERE election_id = ?", (eid,))]
        if roll_hash(roll) != e["roll_hash"]:
            out.append(Finding("critical", "roll_changed",
                               f"election {eid}: voter roll differs from the sealed roll"))
        issued = conn.execute("SELECT COUNT(*) FROM credential_issuance WHERE election_id = ?",
                              (eid,)).fetchone()[0]
        orphan = conn.execute(
            "SELECT COUNT(*) FROM credential_issuance ci WHERE ci.election_id = ? AND NOT EXISTS "
            "(SELECT 1 FROM election_voters ev WHERE ev.election_id = ci.election_id "
            "AND ev.voter_id = ci.voter_id)", (eid,)).fetchone()[0]
        if orphan:
            out.append(Finding("critical", "orphan_credential",
                               f"election {eid}: {n(orphan)} credentials issued to "
                               "non-roll voters"))
        ballots = conn.execute("SELECT token_hash, token, sig FROM ballots WHERE election_id = ?",
                               (eid,)).fetchall()
        if len(ballots) > issued:
            out.append(Finding("critical", "ballot_stuffing",
                               f"election {eid}: ballots ({n(len(ballots))}) exceed credentials "
                               f"({n(issued)})"))
        if issued > len(roll):
            out.append(Finding("critical", "over_issuance",
                               f"election {eid}: credentials ({n(issued)}) exceed voters "
                               f"({n(len(roll))})"))
        pk = keystore.load_public_pem(e["pubkey_pem"])
        bad = sum(1 for b in ballots
                  if hashlib.sha256(b["token"]).digest() != b["token_hash"]
                  or not blind_rsa.verify(pk, b["token"], b["sig"]))
        if bad:
            out.append(Finding("critical", "forged_ballot",
                               f"election {eid}: {n(bad)} ballots with invalid signatures"))
        out += [Finding("critical", "voter_log", p)
                for p in chain.verify_voter_chain(conn, keys.audit, eid)]
        logged = {r[0] for r in conn.execute(
            "SELECT voter_id FROM voter_log WHERE election_id = ? AND action = 'credential_issued'",
            (eid,))}
        issued_ids = {r[0] for r in conn.execute(
            "SELECT voter_id FROM credential_issuance WHERE election_id = ?", (eid,))}
        if logged != issued_ids:
            out.append(Finding("critical", "voter_log",
                               f"election {eid}: credential records and voter log disagree "
                               "(entries removed or added outside the application)"))
        if not sealed:
            seal = None
            for row in conn.execute("SELECT seq, payload FROM audit_log "
                                    "WHERE action = 'voter_log_sealed'"):
                try:
                    p = chain.read_payload(keys, row)
                except (ValueError, fieldenc.FieldDecryptError):
                    continue  # çözülemeyen kayıt: aşağıda "seal mismatch" olarak raporlanır
                if p.get("election_id") == eid:
                    seal = p
            entries, head = chain.voter_log_head(conn, eid)
            if seal != {"election_id": eid, "entries": entries, "head": head}:
                out.append(Finding("critical", "voter_log",
                                   f"election {eid}: voter log differs from the sealed head"))
        if e["status"] in ("closed", "tallied", "archived") and e["privkey_wrapped"] is not None:
            out.append(Finding("critical", "key_not_destroyed",
                               f"election {eid}: private key still present after close"))
    return out


def _clock_findings() -> list[Finding]:
    from ..timekeeping import get_clock
    clock = get_clock()
    out = [Finding("critical" if a.kind in ("clock_rollback", "system_clock_jump") else "warning",
                   "clock", f"{a.at} {a.kind}: {a.detail}") for a in clock.alarms]
    if clock.assurance == "unverified":
        out.append(Finding("warning", "clock", "time is not verified by external sources; "
                                               "elections will not close until it is"))
    elif clock.assurance == "system":
        out.append(Finding("warning", "clock", "time mode is 'system': the server clock is "
                                               "trusted without external confirmation"))
    return out


def _storage_findings(settings) -> list[Finding]:
    """Dosya izinleri ve ana anahtar koruması."""
    from .. import osprotect
    out = [Finding("critical", "filesystem", p)
           for p in osprotect.check(osprotect.protected_dirs(settings))]
    prot = settings.key_protection_in_use()
    if prot == "file":
        out.append(Finding("warning", "key_protection",
                           "master key is stored unencrypted; use DPAPI (Windows) or a "
                           "passphrase: `oysistemi key protect`"))
    if settings.recovery_key_path.exists():
        out.append(Finding("warning", "recovery_key",
                           f"recovery key is still on the server ({settings.recovery_key_path}); "
                           "copy it to offline storage and delete it here"))
    return out


def verify(conn: sqlite3.Connection, keys: Keys, checkpoint_path: Path,
           settings=None) -> list[Finding]:
    findings: list[Finding] = _clock_findings()
    if settings is not None:
        findings += _storage_findings(settings)
    if connection.schema_fingerprint(conn) != connection.expected_schema_fingerprint():
        findings.append(Finding("critical", "schema",
                                "schema/triggers differ from the shipped schema"))
    findings += [Finding("critical", "audit_chain", p)
                 for p in chain.verify_chain(conn, keys.audit)]
    findings += _rowmac_findings(conn, keys)
    findings += _shadow_findings(conn)
    findings += [Finding(sev, "checkpoint", msg)
                 for sev, msg in checkpoint.compare(conn, keys.checkpoint, checkpoint_path)]
    findings += _election_findings(conn, keys)
    return findings
