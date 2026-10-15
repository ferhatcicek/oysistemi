"""Şifreli yedekleme ve geri yükleme.

Yedek dosyası (.oysbak) veritabanının tutarlı bir anlık görüntüsünü (SQLite backup API) ve
checkpoint dosyasını içerir, scrypt + AES-256-GCM ile parolaya bağlanır. Ana anahtar yedeğe
KONMAZ: geri yüklenen veritabanını açmak için ayrıca kurtarma anahtarı gerekir. Böylece
yedeği ele geçiren biri hem yedek parolasını hem kurtarma anahtarını bilmeden hiçbir şey göremez.
"""
from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

from .config import Settings
from .crypto import keyfile
from .db import connection

PURPOSE = "oysistemi/backup"


def create(settings: Settings, out_path: Path, passphrase: str) -> int:
    src = connection.connect(settings.db_path)
    mem = sqlite3.connect(":memory:")
    try:
        src.backup(mem)  # işlem sürerken bile tutarlı anlık görüntü
        image = mem.serialize()
    finally:
        mem.close()
        src.close()
    cps = settings.checkpoint_path.read_text(encoding="utf-8") \
        if settings.checkpoint_path.exists() else ""
    body = json.dumps({"format": "oysistemi-backup", "v": 1,
                       "db": base64.b64encode(image).decode(), "checkpoints": cps}).encode()
    rec = {"format": "oysistemi-backup", "v": 1,
           **keyfile.seal_with_passphrase(body, passphrase, PURPOSE)}
    keyfile.write_new(out_path, json.dumps(rec).encode())
    return len(image)


def restore(settings: Settings, in_path: Path, passphrase: str) -> None:
    if settings.db_path.exists():
        raise FileExistsError(f"database already exists: {settings.db_path}; restore refuses "
                              "to overwrite it")
    rec = json.loads(in_path.read_bytes())
    if rec.get("format") != "oysistemi-backup":
        raise keyfile.KeyFileError("not an OySistemi backup")
    body = json.loads(keyfile.open_with_passphrase(rec, passphrase, PURPOSE))
    image = base64.b64decode(body["db"])
    mem = sqlite3.connect(":memory:")
    try:
        mem.deserialize(image)
        if connection.schema_fingerprint(mem) != connection.expected_schema_fingerprint():
            raise ValueError("backup schema does not match this version of OySistemi")
    finally:
        mem.close()
    keyfile.write_new(settings.db_path, image)
    if body["checkpoints"] and not settings.checkpoint_path.exists():
        settings.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        settings.checkpoint_path.write_text(body["checkpoints"], encoding="utf-8")
