"""Yeni yöneticinin hesabını kendisinin etkinleştirmesi (iki parçalı kayıt belirteci).

Sorun: Öneren yönetici yeni hesabın parolasını belirleseydi, onaydan sonra o hesaba gerçek
kişiden önce girip TOTP'yi kendi telefonuna kaydedebilir ve tek başına İKİ yönetici hesabını
kontrol ederdi. Bu, iki kişi kuralını tek kişiyle aşmak demektir.

Çözüm: Hesap parolasız ("etkinleştirme bekliyor") oluşturulur. Etkinleştirmek için iki parça
gerekir:
  A parçası  öneri anında yalnızca ÖNERENE bir kez gösterilir,
  B parçası  onay anında yalnızca ONAYLAYANA bir kez gösterilir.
Yeni yönetici iki parçayı da alıp kendi parolasını belirler; ardından ilk girişte kendi TOTP'sini
kaydeder. Tek bir yönetici iki parçayı birden bilmediği için hesabı tek başına ele geçiremez.
Sunucuda yalnızca parçaların argon2 özetleri saklanır.
"""
from __future__ import annotations

import json
import secrets
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from ..audit import chain, checkpoint
from ..context import Context
from ..crypto import rowmac
from ..db.connection import IntegrityError, transaction, update_row
from ..timekeeping import get_clock

PREFIX = "enroll:"
TTL_SECONDS = 7 * 86400
MIN_PASSWORD = 12
_ph = PasswordHasher()
_DUMMY = _ph.hash("dummy-enrollment-part")


class EnrollmentError(RuntimeError):
    pass


def new_part() -> str:
    """~128 bit rastgele, elle yazılabilir parça (ör. 'k3f9-...')."""
    raw = secrets.token_hex(16)
    return "-".join(raw[i:i + 4] for i in range(0, 32, 4))


def _norm(part: str) -> str:
    return "".join(ch for ch in part.lower() if ch in "0123456789abcdef")


def hash_part(part: str) -> str:
    return _ph.hash(_norm(part))


def pending_marker(a_hash: str, b_hash: str) -> str:
    """admins.pw_hash alanına yazılan değer: parola değil, etkinleştirme bekleme işareti."""
    expires = int(get_clock().now()) + TTL_SECONDS
    return PREFIX + json.dumps({"a": a_hash, "b": b_hash, "exp": expires}, sort_keys=True)


def is_pending(pw_hash: str) -> bool:
    return pw_hash.startswith(PREFIX)


def _check(h: str, part: str) -> bool:
    try:
        return _ph.verify(h, _norm(part))
    except VerificationError:
        return False


def complete(ctx: Context, username: str, part_a: str, part_b: str, password: str) -> None:
    """İki parça doğruysa yeni yöneticinin kendi parolasını ayarlar."""
    from ..auth import admin_auth

    if len(password) < MIN_PASSWORD:
        raise EnrollmentError(f"password must be at least {MIN_PASSWORD} characters")
    if admin_auth._locked(username):
        raise EnrollmentError("too many failed attempts; try again later")
    with transaction(ctx.conn):
        row = ctx.conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if row is None or not is_pending(row["pw_hash"]):
            # Sabit süre: hesabın var olup olmadığı dışarıdan anlaşılmasın.
            _check(_DUMMY, part_a)
            _check(_DUMMY, part_b)
            admin_auth._fail(username)
            raise EnrollmentError("invalid enrollment")
        row = dict(row)
        if not rowmac.verify(ctx.keys.row_mac, "admins", row):
            raise IntegrityError("admin row MAC invalid")
        data: dict[str, Any] = json.loads(row["pw_hash"][len(PREFIX):])
        ok_a = _check(data["a"], part_a)
        ok_b = _check(data["b"], part_b)  # ikisi de her zaman denetlenir
        if not (ok_a and ok_b):
            admin_auth._fail(username)
            raise EnrollmentError("invalid enrollment")
        if get_clock().now() > data["exp"]:
            raise EnrollmentError("enrollment code expired; propose the admin again")
        chain.record(ctx.conn, ctx.keys, row["id"], "admin_enrolled", {"admin_id": row["id"]})
        update_row(ctx.conn, ctx.keys.row_mac, "admins", {"id": row["id"]},
                   {"pw_hash": _ph.hash(password)})
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
