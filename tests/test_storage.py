"""Depolama güvenliği: alan şifreleme, anahtar koruma, kurtarma, şifreli yedek, dosya izinleri."""
from __future__ import annotations

import dataclasses
import sqlite3
import subprocess
import sys

import pytest
from conftest import approve, close
from helpers import get_credential

from oysistemi import backup, osprotect
from oysistemi.audit import verifier
from oysistemi.config import Settings
from oysistemi.context import initialise, open_context
from oysistemi.crypto import dpapi, keyfile
from oysistemi.elections import service
from oysistemi.voting import ballot_box

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


def test_db_file_contains_no_plaintext_personal_data_or_votes(ctx, clock, settings):
    approve(ctx, "voters_add", {"voters": [
        {"id": "v1", "display_name": "Gizli Ayşe Yılmaz", "email": "gizli.ayse@example.org"},
        {"id": "v2", "display_name": "Gizli Mehmet Kaya", "email": "gizli.mehmet@example.org"},
    ]})
    service.create_election(ctx, "a1", "e1", "Seçim", "single",
                            {"ballot": {"options": ["AdayZümrüt", "AdayFiruze"]},
                             "min_turnout": 1, "closes_at": "2026-10-15T11:00:00Z"})
    approve(ctx, "roll_add", {"election_id": "e1", "voter_ids": ["v1", "v2"]})
    approve(ctx, "election_open", {"election_id": "e1"})
    token, sig = get_credential(ctx, "e1", "v1")
    ballot_box.cast(ctx, "e1", token, sig, {"choice": "AdayZümrüt"})

    raw = settings.db_path.read_bytes()
    for secret in ("Gizli Ayşe", "gizli.ayse@example.org", "Gizli Mehmet",
                   '"choice":"AdayZümrüt"'):
        assert secret.encode() not in raw, f"plaintext found in DB file: {secret}"
    # ...ama uygulama hepsini okuyabiliyor
    close(ctx, clock, "e1")
    assert service.bulletin(ctx, "e1")["result"]["tally"]["counts"]["AdayZümrüt"] == 1


def test_ciphertext_moved_to_another_row_is_rejected(ctx, clock, settings, open_election):
    for v, choice in (("v1", "Ali"), ("v2", "Veli")):
        token, sig = get_credential(ctx, open_election, v)
        ballot_box.cast(ctx, open_election, token, sig, {"choice": choice})
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    (h1, b1), (h2, b2) = raw.execute("SELECT token_hash, ballot FROM ballots").fetchall()
    raw.execute("DROP TRIGGER ballots_no_update")
    raw.execute("UPDATE ballots SET ballot = ? WHERE token_hash = ?", (b2, h1))  # oyları takas
    raw.execute("UPDATE ballots SET ballot = ? WHERE token_hash = ?", (b1, h2))
    ctx.conn.execute("SELECT 1")  # (şema değişti; tally yine de güvenli davranmalı)
    result = service.tally(ctx, open_election)
    assert result["rejected_ballots"] == 2 and result["turnout"] == 0


def test_voter_name_swap_between_rows_is_detected(ctx, settings):
    approve(ctx, "voters_add", {"voters": [{"id": "v1", "display_name": "Bir"},
                                           {"id": "v2", "display_name": "İki"}]})
    raw = sqlite3.connect(settings.db_path, isolation_level=None)
    n1 = raw.execute("SELECT display_name FROM voters WHERE id='v1'").fetchone()[0]
    raw.execute("UPDATE voters SET display_name = ? WHERE id = 'v2'", (n1,))
    codes = {f.code for f in verifier.verify(ctx.conn, ctx.keys, settings.checkpoint_path)}
    assert "row_mac" in codes


# ───────────────────────── Ana anahtar koruması ─────────────────────────

def test_passphrase_protected_key_roundtrip_and_wrong_passphrase():
    master = b"k" * 32
    blob = keyfile.encode(master, "passphrase", "dogru-parola-123")
    assert master not in blob
    assert keyfile.decode(blob, lambda: "dogru-parola-123") == (master, "passphrase")
    with pytest.raises(keyfile.KeyFileError):
        keyfile.decode(blob, lambda: "yanlis-parola-123")
    with pytest.raises(keyfile.KeyFileError):
        keyfile.encode(master, "passphrase", "kisa")


@windows_only
def test_dpapi_protected_key_roundtrip():
    master = b"d" * 32
    blob = keyfile.encode(master, "dpapi")
    assert master not in blob
    assert keyfile.decode(blob) == (master, "dpapi")


@windows_only
def test_dpapi_blob_tampering_fails():
    blob = dpapi.protect(b"x" * 32)
    with pytest.raises(PermissionError):
        dpapi.unprotect(blob[:-4] + b"\0\0\0\0")


def test_recovery_key_restores_access_after_server_loss(tmp_path, clock):
    s = Settings(db_path=tmp_path / "a" / "data" / "oys.db",
                 master_key_path=tmp_path / "a" / "secrets" / "master.key",
                 checkpoint_path=tmp_path / "a" / "cp" / "c.jsonl", rsa_bits=2048,
                 key_protection="dpapi" if sys.platform == "win32" else "file")
    initialise(s, recovery_passphrase="kurtarma-parolasi-123")
    original = s.load_keys()
    assert s.recovery_key_path.exists()

    # Sunucu kayboldu: ana anahtar dosyası yok, elimizde yalnızca kurtarma dosyası var
    rec = s.recovery_key_path.read_bytes()
    s.master_key_path.unlink()
    master, prot = keyfile.decode(rec, lambda: "kurtarma-parolasi-123")
    assert prot == "passphrase"
    keyfile.write_new(s.master_key_path, keyfile.encode(master, s.key_protection))
    assert s.load_keys() == original


def test_verifier_warns_about_unprotected_key_and_recovery_on_server(tmp_path, clock):
    s = Settings(db_path=tmp_path / "data" / "oys.db",
                 master_key_path=tmp_path / "secrets" / "master.key",
                 checkpoint_path=tmp_path / "cp" / "c.jsonl", rsa_bits=2048)
    initialise(s, recovery_passphrase="kurtarma-parolasi-123")
    c = open_context(s)
    codes = {f.code for f in verifier.verify(c.conn, c.keys, s.checkpoint_path, s)}
    c.close()
    assert {"key_protection", "recovery_key"} <= codes


# ───────────────────────── Şifreli yedek ─────────────────────────

def test_encrypted_backup_roundtrip(ctx, settings, tmp_path, open_election):
    out = tmp_path / "yedek.oysbak"
    backup.create(settings, out, "yedek-parolasi-123")
    assert b"SQLite format 3" not in out.read_bytes()  # yedek dosyası şifreli

    with pytest.raises(keyfile.KeyFileError):
        backup.restore(dataclasses.replace(settings, db_path=tmp_path / "x" / "r.db"), out,
                       "yanlis-parola-123")
    with pytest.raises(FileExistsError):  # var olan veritabanının üzerine yazmaz
        backup.restore(settings, out, "yedek-parolasi-123")

    target = dataclasses.replace(settings, db_path=tmp_path / "restore" / "data" / "oys.db",
                                 checkpoint_path=tmp_path / "restore" / "cp" / "c.jsonl")
    target.db_path.parent.mkdir(parents=True)
    backup.restore(target, out, "yedek-parolasi-123")
    c = open_context(target)  # aynı ana anahtarla açılıyor
    try:
        assert service.get_election(c, open_election)["status"] == "open"
        crit = [f for f in verifier.verify(c.conn, c.keys, target.checkpoint_path)
                if f.severity == "critical"]
        assert crit == []
    finally:
        c.close()


# ───────────────────────── Dosya izinleri ─────────────────────────

def test_initialise_locks_down_folders(settings):
    initialise(settings)
    assert osprotect.check(osprotect.protected_dirs(settings)) == []


@windows_only
def test_acl_check_detects_world_readable_folder(tmp_path):
    d = tmp_path / "acik"
    d.mkdir()
    # "Users" (S-1-5-32-545) grubuna okuma izni ver — Türkçe/İngilizce Windows'ta aynı SID
    subprocess.run([osprotect._sys32("icacls.exe"), str(d), "/grant", "*S-1-5-32-545:(OI)(CI)R"],
                   capture_output=True, check=True)
    problems = osprotect.check([d])
    assert any("S-1-5-32-545" in p for p in problems)
    osprotect.harden(d)
    assert osprotect.check([d]) == []


def test_refuses_to_harden_broad_directories():
    from pathlib import Path
    with pytest.raises(ValueError):
        osprotect.harden(Path.home())
