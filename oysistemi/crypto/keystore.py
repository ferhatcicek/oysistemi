"""Seçim özel anahtarlarının AES-GCM ile sarmalanması.

Sarmalanmış anahtar DB'de durur, sarmalama anahtarı DB dışındaki ana anahtardan türetilir.
AAD olarak seçim kimliği kullanılır: A seçiminin anahtarı B seçiminin satırına
kopyalanırsa açılmaz.
"""
from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12


def wrap_private_key(wrap_key: bytes, election_id: str, sk: rsa.RSAPrivateKey) -> bytes:
    der = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(wrap_key).encrypt(nonce, der, election_id.encode())


def unwrap_private_key(wrap_key: bytes, election_id: str, blob: bytes) -> rsa.RSAPrivateKey:
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    der = AESGCM(wrap_key).decrypt(nonce, ct, election_id.encode())
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("not an RSA key")
    return key


def public_pem(sk: rsa.RSAPrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)


def public_json(pem: bytes) -> dict[str, object]:
    """Tarayıcıdaki blindsig.js'in beklediği biçim."""
    pk = load_public_pem(pem)
    nums = pk.public_numbers()
    spki = pk.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"n": format(nums.n, "x"), "e": format(nums.e, "x"), "bits": pk.key_size,
            "spki": base64.b64encode(spki).decode()}


def load_public_pem(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("not an RSA key")
    return key
