"""Windows DPAPI (CryptProtectData) — ctypes ile, ek bağımlılık olmadan.

Korunan veri yalnızca AYNI Windows kullanıcı hesabı ve AYNI makinede çözülebilir. Dosyalar
başka bir bilgisayara veya başka bir hesaba kopyalanırsa çözülemez.
"""
from __future__ import annotations

import ctypes
import sys

CRYPTPROTECT_UI_FORBIDDEN = 0x01
ENTROPY = b"oysistemi/master-key/v1"


def available() -> bool:
    return sys.platform == "win32"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _take(blob: _Blob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect(data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI is only available on Windows")
    inp, _keep1 = _blob(data)
    ent, _keep2 = _blob(ENTROPY)
    out = _Blob()
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(inp), "oysistemi", ctypes.byref(ent), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise ctypes.WinError()
    return _take(out)


def unprotect(data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI is only available on Windows")
    inp, _keep1 = _blob(data)
    ent, _keep2 = _blob(ENTROPY)
    out = _Blob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(inp), None, ctypes.byref(ent), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise PermissionError(
            "DPAPI could not decrypt the master key. It can only be opened by the Windows "
            "account (on the same computer) that created it. Use the recovery key to move it.")
    return _take(out)
