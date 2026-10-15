"""SQLite bağlantısı, işlem (transaction) yardımcıları ve MAC'li satır yazımı."""
from __future__ import annotations

import functools
import hashlib
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any

from ..crypto import rowmac

SCHEMA_SQL = resources.files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")


def connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, isolation_level=None, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Silinen sayfalar sıfırlanır: imha edilen anahtarlar/eski veriler dosyada kalmaz.
    conn.execute("PRAGMA secure_delete = ON")
    # WAL yerine rollback journal: WAL dosyası oy eklemelerinin sırasını geçici olarak tutar.
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA busy_timeout = 10000")
    # Geçici tablolar/sıralamalar diske (şifresiz geçici dosyalara) yazılmasın.
    conn.execute("PRAGMA temp_store = MEMORY")
    # Şemadaki tetikleyici/görünümler güvenilmeyen SQL fonksiyonlarını çağıramasın.
    conn.execute("PRAGMA trusted_schema = OFF")
    # Bozuk/elle değiştirilmiş sayfaları okurken tespit et.
    conn.execute("PRAGMA cell_size_check = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'voters'").fetchone():
        raise RuntimeError("database already initialised")
    conn.executescript(SCHEMA_SQL)


def schema_fingerprint(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").fetchall()
    h = hashlib.sha256()
    for r in rows:
        h.update(repr(tuple(r)).encode())
    return h.hexdigest()


@functools.cache
def expected_schema_fingerprint() -> str:
    mem = sqlite3.connect(":memory:")
    mem.executescript(SCHEMA_SQL)
    try:
        return schema_fingerprint(mem)
    finally:
        mem.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE: yazma kilidi baştan alınır, eşzamanlı çift oy yarışları sıralanır.

    Çıkışta denetim bağlamı (_ctx) her durumda temizlenir; böylece bir sonraki bant dışı
    değişiklik yanlışlıkla meşru bir denetim kaydına bağlanmaz.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("UPDATE _ctx SET audit_seq = NULL WHERE id = 1")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


_ALLOWED_TABLES = frozenset(rowmac.MAC_FIELDS)


def _check_table(table: str) -> None:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"table not allowed: {table}")


def insert_row(conn: sqlite3.Connection, mac_key: bytes, table: str,
               row: Mapping[str, Any]) -> None:
    _check_table(table)
    data = dict(row)
    data["row_mac"] = rowmac.compute(mac_key, table, data)
    cols = ", ".join(data)
    marks = ", ".join(f":{c}" for c in data)
    conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", data)


def update_row(conn: sqlite3.Connection, mac_key: bytes, table: str,
               pk: Mapping[str, Any], changes: Mapping[str, Any]) -> dict[str, Any]:
    """Satırı okur, MAC'ini doğrular, değişiklikleri uygular ve yeni MAC'i yazar.

    Mevcut MAC geçersizse güncelleme reddedilir: kurcalanmış bir satır meşru bir
    güncellemeyle "aklanamaz".
    """
    _check_table(table)
    if set(pk) != set(rowmac.PRIMARY_KEYS[table]):
        raise ValueError("primary key mismatch")
    where = " AND ".join(f"{k} = :pk_{k}" for k in pk)
    params = {f"pk_{k}": v for k, v in pk.items()}
    current = conn.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchone()
    if current is None:
        raise LookupError(f"{table} row not found: {dict(pk)}")
    current = dict(current)
    if not rowmac.verify(mac_key, table, current):
        raise IntegrityError(f"row MAC invalid for {table} {dict(pk)}; refusing to update")
    unknown = set(changes) - set(rowmac.MAC_FIELDS[table])
    if unknown:
        raise ValueError(f"unknown columns: {unknown}")
    current.update(changes)
    current["row_mac"] = rowmac.compute(mac_key, table, current)
    sets = ", ".join(f"{c} = :{c}" for c in [*changes, "row_mac"])
    conn.execute(f"UPDATE {table} SET {sets} WHERE {where}", {**current, **params})
    return current


class IntegrityError(Exception):
    """Kurcalama şüphesi: MAC veya zincir doğrulaması başarısız."""
