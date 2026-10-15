"""Ayarlar ve gizli anahtar yönetimi.

Ana anahtar (master key) veritabanı dosyasından AYRI bir yerde tutulur. DB dosyası çalınsa
ya da doğrudan düzenlense bile satır MAC'leri, denetim zinciri MAC'leri ve seçim özel
anahtarları bu anahtar olmadan üretilemez / açılamaz.
"""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_LEN = 32


@dataclass(frozen=True)
class Keys:
    """Ana anahtardan HKDF ile türetilmiş, amaca özel anahtarlar."""

    row_mac: bytes
    audit: bytes
    wrap: bytes
    checkpoint: bytes
    session: bytes
    field: bytes  # hassas sütunların AES-256-GCM şifrelemesi

    @classmethod
    def derive(cls, master: bytes) -> Keys:
        if len(master) != MASTER_KEY_LEN:
            raise ValueError("master key must be 32 bytes")

        def sub(label: bytes) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                        info=b"oysistemi/" + label).derive(master)

        return cls(row_mac=sub(b"rowmac"), audit=sub(b"audit"),
                   wrap=sub(b"wrap"), checkpoint=sub(b"checkpoint"),
                   session=sub(b"session"), field=sub(b"field"))


@dataclass(frozen=True)
class Settings:
    db_path: Path
    master_key_path: Path
    checkpoint_path: Path
    rsa_bits: int = 3072
    default_required_approvals: int = 1
    # E-posta: smtp_host boşsa e-postalar outbox_dir'e dosya olarak yazılır (yalnızca geliştirme).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "oysistemi@localhost"
    outbox_dir: Path | None = None
    # HTTPS arkasında True kalmalı; yalnızca düz HTTP ile yerel testte False yapılır.
    cookie_secure: bool = True
    # Zaman: 'ntp' = birden çok NTP sunucusunun uzlaşması (önerilen); 'system' = yalnızca
    # sistem saati (internetsiz kurulumlar; sonuçlarda düşük güvence olarak belirtilir).
    time_mode: str = "system"
    time_sources: tuple[str, ...] = ("time.cloudflare.com", "time.google.com",
                                     "pool.ntp.org", "time.windows.com")
    time_quorum: int = 2
    time_tolerance: float = 30.0
    timezone: str = "Europe/Istanbul"
    # Ana anahtar koruması: 'dpapi' (Windows), 'passphrase' veya 'file' (bkz. crypto/keyfile.py)
    key_protection: str = "file"
    # AGPL-3.0 §13: sistemi ağ üzerinden kullananlara kaynak koduna erişim sunulmalı.
    source_url: str = ""

    @classmethod
    def from_env(cls, base: Path | None = None) -> Settings:
        base = base or Path(os.environ.get("OYS_HOME", "."))
        return cls(
            db_path=Path(os.environ.get("OYS_DB", base / "data" / "oysistemi.db")),
            master_key_path=Path(os.environ.get("OYS_MASTER_KEY", base / "secrets" / "master.key")),
            checkpoint_path=Path(os.environ.get("OYS_CHECKPOINTS",
                                                base / "checkpoints" / "checkpoints.jsonl")),
            rsa_bits=int(os.environ.get("OYS_RSA_BITS", 3072)),
            default_required_approvals=int(os.environ.get("OYS_REQUIRED_APPROVALS", 1)),
            smtp_host=os.environ.get("OYS_SMTP_HOST", ""),
            smtp_port=int(os.environ.get("OYS_SMTP_PORT", 587)),
            smtp_user=os.environ.get("OYS_SMTP_USER", ""),
            smtp_password=os.environ.get("OYS_SMTP_PASSWORD", ""),
            smtp_from=os.environ.get("OYS_SMTP_FROM", "oysistemi@localhost"),
            outbox_dir=Path(os.environ.get("OYS_OUTBOX", base / "outbox")),
            cookie_secure=os.environ.get("OYS_COOKIE_SECURE", "1") != "0",
            time_mode=os.environ.get("OYS_TIME_MODE", "ntp"),
            time_sources=tuple(h.strip() for h in os.environ.get(
                "OYS_TIME_SOURCES",
                "time.cloudflare.com,time.google.com,pool.ntp.org,time.windows.com").split(",")
                if h.strip()),
            time_quorum=int(os.environ.get("OYS_TIME_QUORUM", 2)),
            time_tolerance=float(os.environ.get("OYS_TIME_TOLERANCE", 30)),
            timezone=os.environ.get("OYS_TZ", "Europe/Istanbul"),
            source_url=os.environ.get("OYS_SOURCE_URL", ""),
            key_protection=os.environ.get(
                "OYS_KEY_PROTECTION", "dpapi" if sys.platform == "win32" else "file"),
        )

    @property
    def recovery_key_path(self) -> Path:
        return self.master_key_path.with_name("KURTARMA_ANAHTARI.oyskey")

    def load_keys(self) -> Keys:
        from .crypto import keyfile
        master, _ = keyfile.decode(self.master_key_path.read_bytes(), _passphrase_from_env)
        return Keys.derive(master)

    def key_protection_in_use(self) -> str:
        raw = self.master_key_path.read_bytes()
        if len(raw) == MASTER_KEY_LEN:
            return "file"
        import json
        return json.loads(raw).get("protection", "?") if raw.startswith(b"{") else "?"

    def create_master_key(self, *, recovery_passphrase: str | None,
                          passphrase: str | None = None) -> None:
        """Yeni ana anahtar üretir, seçilen modla korur ve (verilirse) kurtarma anahtarı yazar."""
        from .crypto import keyfile
        if self.master_key_path.exists():
            raise FileExistsError(f"master key already exists: {self.master_key_path}")
        master = secrets.token_bytes(MASTER_KEY_LEN)
        keyfile.write_new(self.master_key_path,
                          keyfile.encode(master, self.key_protection, passphrase))
        if recovery_passphrase is not None:
            keyfile.write_new(self.recovery_key_path,
                              keyfile.encode(master, "passphrase", recovery_passphrase))


def _passphrase_from_env() -> str:
    value = os.environ.get("OYS_PASSPHRASE")
    if value:
        return value
    if sys.stdin and sys.stdin.isatty():
        import getpass
        return getpass.getpass("Ana anahtar parolası: ")
    raise RuntimeError("master key is passphrase-protected; set OYS_PASSPHRASE")
