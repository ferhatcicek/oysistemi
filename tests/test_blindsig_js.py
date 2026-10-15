"""Tarayıcı (blindsig.js) ↔ sunucu (Python) kör imza uyumluluğu."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from oysistemi.crypto import blind_rsa, keystore

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "oysistemi" / "web" / "static" / "blindsig.js"
DRIVER = Path(__file__).with_name("js_driver.js")

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def node(req: dict) -> dict:
    out = subprocess.run(["node", str(DRIVER), str(JS)], input=json.dumps(req), text=True,
                         capture_output=True, check=True, timeout=60)
    return json.loads(out.stdout)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_browser_blind_python_sign_roundtrip(bits):
    sk = blind_rsa.generate_key(bits)
    pk_json = keystore.public_json(keystore.public_pem(sk))
    c = node({"op": "blind", "pk": pk_json})
    blinded = base64.b64decode(c["blinded"])
    prepared = base64.b64decode(c["prepared"])
    assert prepared not in blinded

    blind_sig = blind_rsa.blind_sign(sk, blinded)
    f = node({"op": "finalize", "pk": pk_json, "prepared": c["prepared"], "inv": c["inv"],
              "blind_sig": base64.b64encode(blind_sig).decode()})
    sig = base64.b64decode(f["sig"])
    assert blind_rsa.verify(sk.public_key(), prepared, sig)  # sunucu da kabul ediyor


def test_python_signature_verifies_in_browser_and_rejects_tamper():
    sk = blind_rsa.generate_key(2048)
    pk_json = keystore.public_json(keystore.public_pem(sk))
    prepared = blind_rsa.prepare(b"z" * 32)
    blinded, inv = blind_rsa.blind(sk.public_key(), prepared)
    sig = blind_rsa.finalize(sk.public_key(), prepared, blind_rsa.blind_sign(sk, blinded), inv)
    b64 = lambda x: base64.b64encode(x).decode()  # noqa: E731
    assert node({"op": "verify", "pk": pk_json, "prepared": b64(prepared), "sig": b64(sig)})["ok"]
    assert not node({"op": "verify", "pk": pk_json, "prepared": b64(prepared + b"x"),
                     "sig": b64(sig)})["ok"]
