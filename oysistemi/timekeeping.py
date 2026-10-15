"""Güvenilir zaman: sistem saatinin değiştirilmesine karşı katmanlı savunma.

Tehdit: Sunucuya erişimi olan biri sistem saatini
  • İLERİ alarak oylamayı erken kapatıp sonucu (ve katılımı) görmeye,
  • GERİ alarak süresi dolmuş oylamaya oy eklemeye ya da denetim kaydını geriye tarihlemeye
çalışabilir.

Katmanlar:
  1. Dış kaynak uzlaşması: Açılışta ve düzenli aralıklarla birden çok bağımsız NTP sunucusu
     sorgulanır; en az `quorum` kaynağın medyana `tolerance` içinde uyması gerekir.
  2. Monotonik çapa: Uygulama zamanı = çapa + (monotonik sayaç farkı). Çalışma sırasında
     sistem saatinin değiştirilmesi uygulama zamanını ETKİLEMEZ, yalnızca alarm üretir.
  3. En yüksek su işareti: Denetim zincirindeki son zaman damgasının gerisine düşen bir saat
     "geri alma" sayılır; zamana bağlı tüm işlemler durur (bkz. audit/chain.py).
  4. Güvence seviyesi: 'ntp' (dış kaynaklarla doğrulandı) veya 'system' (yalnızca sistem
     saati — çevrimdışı kurulumlar için, sonuçlarda açıkça belirtilir). 'unverified' ise
     kapanış ve sayım YAPILMAZ.

Not: NTP kimlik doğrulamasız bir protokoldür; birden fazla bağımsız kaynak ağ düzeyinde
sahteciliği zorlaştırır ama imkânsız kılmaz. NTS (RFC 8915) ileride eklenebilir.
"""
from __future__ import annotations

import socket
import statistics
import struct
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

NTP_EPOCH_OFFSET = 2208988800  # 1900-01-01 → 1970-01-01
DEFAULT_SOURCES = ("time.cloudflare.com", "time.google.com", "pool.ntp.org", "time.windows.com")


class ClockError(RuntimeError):
    """Zamana güvenilemiyor: zamana bağlı işlem reddedildi."""


def sntp_query(host: str, timeout: float = 3.0) -> float:
    """SNTP (RFC 4330). Dönüş: sunucu saatine göre, bu sorgunun tamamlandığı anın Unix zamanı."""
    packet = b"\x1b" + 47 * b"\0"  # LI=0, VN=3, Mode=3 (istemci)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.sendto(packet, (host, 123))
        data, _ = s.recvfrom(512)
        t3 = time.monotonic()
    if len(data) < 48:
        raise OSError("short NTP reply")
    stratum = data[1]
    if stratum == 0 or stratum > 15:
        raise OSError(f"unsynchronised NTP server (stratum {stratum})")
    secs, frac = struct.unpack("!II", data[40:48])  # sunucunun gönderim zamanı
    server_tx = secs - NTP_EPOCH_OFFSET + frac / 2**32
    return server_tx + (t3 - t0) / 2  # yanıt yolda geçen sürenin yarısı kadar eskidir


@dataclass
class Alarm:
    at: str
    kind: str
    detail: str


@dataclass
class TrustedClock:
    mode: str = "system"  # 'ntp' | 'system'
    sources: Sequence[str] = DEFAULT_SOURCES
    quorum: int = 2
    tolerance: float = 30.0  # saniye
    query: Callable[[str], float] = sntp_query
    wall: Callable[[], float] = time.time
    mono: Callable[[], float] = time.monotonic
    assurance: str = "unverified"
    alarms: list[Alarm] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in ("ntp", "system"):
            raise ValueError("time mode must be 'ntp' or 'system'")
        self._lock = threading.Lock()
        self._anchor_wall = self.wall()
        self._anchor_mono = self.mono()
        self._tampered = False
        if self.mode == "system":
            self.assurance = "system"

    # ── zaman ──
    def now(self) -> float:
        with self._lock:
            return self._anchor_wall + (self.mono() - self._anchor_mono)

    def now_dt(self) -> datetime:
        return datetime.fromtimestamp(self.now(), UTC)

    def iso(self) -> str:
        return self.now_dt().strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── senkronizasyon ──
    def sync(self) -> bool:
        """Dış kaynaklardan uzlaşmalı zaman alır. Başarılıysa çapayı günceller."""
        if self.mode == "system":
            return True
        readings = []
        for host in self.sources:
            try:
                ext = self.query(host)
                readings.append((ext, self.mono()))
            except OSError:
                continue
        if len(readings) < self.quorum:
            self._alarm("ntp_unavailable",
                        f"only {len(readings)} of {len(self.sources)} time sources answered")
            if self.assurance == "ntp":
                return False  # önceki doğrulanmış çapayı koru
            self.assurance = "unverified"
            return False
        # Okumaları aynı monotonik ana taşı, medyana uyanları say.
        ref_mono = readings[-1][1]
        aligned = [ext + (ref_mono - m) for ext, m in readings]
        median = statistics.median(aligned)
        agreeing = [a for a in aligned if abs(a - median) <= self.tolerance]
        if len(agreeing) < self.quorum:
            self._alarm("ntp_disagreement", "time sources disagree; refusing to trust any")
            self.assurance = "unverified"
            return False
        trusted = statistics.median(agreeing)
        with self._lock:
            drift = (self._anchor_wall + (ref_mono - self._anchor_mono)) - trusted
            self._anchor_wall, self._anchor_mono = trusted, ref_mono
        if self.assurance == "ntp" and abs(drift) > self.tolerance:
            self._alarm("app_clock_drift", f"application clock drifted {drift:+.0f}s from NTP")
        system_offset = self.wall() - self.now()
        if abs(system_offset) > self.tolerance:
            self._alarm("system_clock_wrong",
                        f"system clock is {system_offset:+.0f}s off trusted time; ignoring it")
        self.assurance = "ntp"
        return True

    def check_jump(self) -> float:
        """Sistem saati uygulama zamanından saparsa alarm üretir. Sapmayı döndürür."""
        offset = self.wall() - self.now()
        if abs(offset) > self.tolerance:
            self._alarm("system_clock_jump",
                        f"system clock moved {offset:+.0f}s relative to the monotonic clock")
        return offset

    def mark_tampered(self, detail: str) -> None:
        self._tampered = True
        self._alarm("clock_rollback", detail)

    # ── güvenlik kapıları ──
    def require_sane(self) -> None:
        """Oy verme gibi işlemler için: geri alma tespit edilmemiş olmalı."""
        if self._tampered:
            raise ClockError("clock tampering detected; time-dependent actions are suspended")

    def require_trusted(self) -> None:
        """Kapanış/sayım için: zaman dış kaynaklarla doğrulanmış (veya bilinçli 'system')."""
        self.require_sane()
        if self.assurance == "unverified":
            raise ClockError("time is not verified by external sources; closing is postponed")

    def _alarm(self, kind: str, detail: str) -> None:
        a = Alarm(at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), kind=kind, detail=detail)
        with self._lock:
            if not self.alarms or (self.alarms[-1].kind, self.alarms[-1].detail) != (kind, detail):
                self.alarms.append(a)
                del self.alarms[:-100]


_clock = TrustedClock(mode="system")


def get_clock() -> TrustedClock:
    return _clock


def set_clock(clock: TrustedClock) -> None:
    global _clock
    _clock = clock


def parse_iso(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
