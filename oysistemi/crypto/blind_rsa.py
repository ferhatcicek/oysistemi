"""RSA kör imza — RFC 9474, RSABSSA-SHA384-PSS-Randomized.

Akış:
    istemci:  prepared = prepare(token)               # 32 bayt rastgele önek + mesaj
              blinded, inv = blind(pk, prepared)      # sunucu 'prepared'ı GÖREMEZ
    sunucu:   blind_sig = blind_sign(sk, blinded)
    istemci:  sig = finalize(pk, prepared, blind_sig, inv)
    herkes:   verify(pk, prepared, sig)               # standart RSASSA-PSS doğrulaması

Sunucu yalnızca 'blinded' değerini görür; r körleme faktörü rastgele olduğu için
'blinded' ile sonradan gelen (prepared, sig) çifti arasında hesaplanabilir bir bağ yoktur.
"""
from __future__ import annotations

import hashlib
import secrets
from math import gcd

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HASH = hashlib.sha384
H_LEN = 48
SALT_LEN = 48
PREFIX_LEN = 32


class BlindSignatureError(Exception):
    pass


def _i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += HASH(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _emsa_pss_encode(msg: bytes, em_bits: int, salt: bytes) -> bytes:
    """RFC 8017 §9.1.1."""
    m_hash = HASH(msg).digest()
    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + len(salt) + 2:
        raise BlindSignatureError("encoding error")
    h = HASH(b"\x00" * 8 + m_hash + salt).digest()
    ps = b"\x00" * (em_len - len(salt) - H_LEN - 2)
    db = ps + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - H_LEN - 1), strict=False))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def generate_key(bits: int = 3072) -> rsa.RSAPrivateKey:
    if bits < 2048:
        raise ValueError("RSA key must be at least 2048 bits")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def prepare(msg: bytes) -> bytes:
    """RFC 9474 §4.1 — randomized varyant: mesajın önüne 32 bayt rastgelelik eklenir."""
    return secrets.token_bytes(PREFIX_LEN) + msg


def blind(pk: rsa.RSAPublicKey, prepared_msg: bytes,
          *, _salt: bytes | None = None, _r: int | None = None) -> tuple[bytes, bytes]:
    """RFC 9474 §4.2. Dönüş: (blinded_msg, inv). `_salt`/`_r` yalnızca testler içindir."""
    nums = pk.public_numbers()
    n, e = nums.n, nums.e
    k = (pk.key_size + 7) // 8
    salt = _salt if _salt is not None else secrets.token_bytes(SALT_LEN)
    m = _os2ip(_emsa_pss_encode(prepared_msg, pk.key_size - 1, salt))
    if gcd(m, n) != 1:
        raise BlindSignatureError("invalid input")
    while True:
        r = _r if _r is not None else secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break
        if _r is not None:
            raise BlindSignatureError("invalid blind")
    inv = pow(r, -1, n)
    z = (m * pow(r, e, n)) % n
    return _i2osp(z, k), _i2osp(inv, k)


def blind_sign(sk: rsa.RSAPrivateKey, blinded_msg: bytes) -> bytes:
    """RFC 9474 §4.3 — sunucu tarafı. Hatalı hesaplamaya karşı imza kendini doğrular."""
    priv = sk.private_numbers()
    n, e = priv.public_numbers.n, priv.public_numbers.e
    k = (sk.key_size + 7) // 8
    if len(blinded_msg) != k:
        raise BlindSignatureError("unexpected input size")
    m = _os2ip(blinded_msg)
    if not 0 < m < n:
        raise BlindSignatureError("message representative out of range")
    s = pow(m, priv.d, n)
    if pow(s, e, n) != m:  # hata enjeksiyonu (fault) saldırılarına karşı
        raise BlindSignatureError("signing failure")
    return _i2osp(s, k)


def finalize(pk: rsa.RSAPublicKey, prepared_msg: bytes, blind_sig: bytes, inv: bytes) -> bytes:
    """RFC 9474 §4.4 — istemci tarafı körlemeyi kaldırır ve imzayı doğrular."""
    n = pk.public_numbers().n
    k = (pk.key_size + 7) // 8
    if len(blind_sig) != k:
        raise BlindSignatureError("unexpected input size")
    s = (_os2ip(blind_sig) * _os2ip(inv)) % n
    sig = _i2osp(s, k)
    if not verify(pk, prepared_msg, sig):
        raise BlindSignatureError("invalid signature")
    return sig


def verify(pk: rsa.RSAPublicKey, prepared_msg: bytes, sig: bytes) -> bool:
    """Standart RSASSA-PSS (SHA-384, MGF1-SHA-384, salt 48) — bağımsız kütüphane ile."""
    try:
        pk.verify(sig, prepared_msg,
                  padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=SALT_LEN),
                  hashes.SHA384())
        return True
    except InvalidSignature:
        return False
