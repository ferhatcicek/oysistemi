"""İşletim sistemi düzeyinde dosya koruması (Windows ACL / POSIX izinleri).

Windows'ta yeni klasörler üst klasörün izinlerini devralır; bu genellikle "Authenticated
Users: Değiştir" ve "Users: Oku" demektir, yani makinede oturum açan HERKES veritabanını ve
anahtarı okuyabilir. POSIX `chmod 0600` Windows'ta etkisizdir. Bu modül:

  harden(dir)  Devralmayı keser; yalnızca servisi çalıştıran hesaba ve SYSTEM'e tam yetki verir.
  check(dirs)  İzin verilmeyen bir hesabın erişimi var mı? (SID ile; Türkçe/İngilizce Windows'ta
               aynı çalışır — "Everyone" ile "Herkes" aynı SID'dir.)
"""
from __future__ import annotations

import os

# Yalnızca System32'deki sabit araçlar çağrılır; kabuk (shell) kullanılmaz.
import subprocess  # nosec B404
import sys
from pathlib import Path

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
CREATOR_OWNER_SID = "S-1-3-0"


def restrict_umask() -> None:
    """POSIX: süreçten sonra oluşan her dosya (DB, journal, checkpoint) yalnızca sahibine açık.

    Windows'ta etkisizdir; orada yeni dosyalar kilitli klasörün ACL'ini devralır.
    """
    if sys.platform != "win32":
        os.umask(0o077)


def _sys32(exe: str) -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=60,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def current_user_sid() -> str:
    out = _run([_sys32("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    if out.returncode != 0:
        raise OSError("cannot determine current user SID")
    line = out.stdout.decode("mbcs" if sys.platform == "win32" else "utf-8", "replace").strip()
    return line.rsplit(",", 1)[-1].strip().strip('"')


def _unsafe_target(path: Path) -> bool:
    p = path.resolve()
    return p.parent == p or p == Path.home().resolve() or len(p.parts) <= 2


def harden(path: Path) -> None:
    """Klasörü yalnızca mevcut hesap (+ SYSTEM) erişebilir hale getirir."""
    path.mkdir(parents=True, exist_ok=True)
    if _unsafe_target(path):
        raise ValueError(f"refusing to change permissions of a broad directory: {path}")
    if sys.platform == "win32":
        sid = current_user_sid()
        # 1) Birinin AÇIKÇA eklediği izinleri de sil (/grant:r yalnızca listelenen hesapları,
        #    /inheritance:r yalnızca devralınanları etkiler; tek başlarına yetmez).
        _run([_sys32("icacls.exe"), str(path), "/reset", "/Q"])
        # 2) Devralmayı kes ve yalnızca bu hesap + SYSTEM'e yetki ver (tek komutta: arada
        #    kendimizi kilitlemeyelim).
        res = _run([_sys32("icacls.exe"), str(path), "/inheritance:r",
                    "/grant:r", f"*{sid}:(OI)(CI)F", f"*{SYSTEM_SID}:(OI)(CI)F", "/Q"])
        if res.returncode != 0:
            detail = (res.stdout + res.stderr).decode("mbcs", "replace")
            raise OSError(f"icacls failed for {path}: {detail}")
        # İçerideki dosyaların açık izinlerini sıfırla: yalnızca korunan klasörden devralsınlar.
        if any(path.iterdir()):
            _run([_sys32("icacls.exe"), str(path / "*"), "/reset", "/T", "/C", "/Q"])
    else:
        os.chmod(path, 0o700)
        for root, dirs, files in os.walk(path):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
            for f in files:
                os.chmod(os.path.join(root, f), 0o600)


_PS = r"""
$ErrorActionPreference = 'Stop'
foreach ($p in ($env:OYS_ACL_PATHS -split "`n")) {
  if (-not $p) { continue }
  $acl = Get-Acl -LiteralPath $p
  foreach ($a in $acl.Access) {
    try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { $sid = $a.IdentityReference.Value }
    "{0}|{1}|{2}|{3}" -f $p, $sid, $a.AccessControlType, $a.IdentityReference.Value
  }
}
"""


def check(paths: list[Path]) -> list[str]:
    """Yetkisiz erişim izni olan yolları raporlar."""
    paths = [p for p in paths if p.exists()]
    if not paths:
        return []
    problems: list[str] = []
    if sys.platform == "win32":
        try:
            allowed = {current_user_sid(), SYSTEM_SID, ADMINISTRATORS_SID, CREATOR_OWNER_SID}
            # Yollar ortam değişkeniyle aktarılır: -Command'a ek argüman verilirse PowerShell
            # onları komut metninin parçası sanar.
            # PSModulePath çıkarılır: süreç PowerShell 7 (pwsh) içinden başlatıldıysa bu
            # değişken PS7 modül yollarını taşır ve Windows PowerShell 5.1 Get-Acl'i
            # (Microsoft.PowerShell.Security) yükleyemez.
            env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
            env["OYS_ACL_PATHS"] = "\n".join(str(p.resolve()) for p in paths)
            res = subprocess.run(
                [_sys32(r"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile",
                 "-NonInteractive", "-Command", _PS], capture_output=True, timeout=60,
                env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [f"cannot read permissions: {exc}"]
        if res.returncode != 0:
            return ["cannot read permissions: "
                    + res.stderr.decode("mbcs", "replace").strip()[:200]]
        for line in res.stdout.decode("mbcs", "replace").splitlines():
            parts = line.strip().split("|")
            if len(parts) != 4:
                continue
            p, sid, kind, name = parts
            if kind == "Allow" and sid not in allowed:
                msg = f"{p}: '{name}' ({sid}) can access this folder"
                if msg not in problems:
                    problems.append(msg)
    else:
        for p in paths:
            for root, _dirs, files in os.walk(p):
                for name in [root, *(os.path.join(root, f) for f in files)]:
                    mode = os.stat(name).st_mode
                    if mode & 0o077:
                        problems.append(
                            f"{name}: readable by other users (mode {oct(mode & 0o777)})")
    return problems


def protected_dirs(settings) -> list[Path]:
    dirs = {settings.db_path.parent, settings.master_key_path.parent,
            settings.checkpoint_path.parent}
    if settings.outbox_dir is not None:
        dirs.add(settings.outbox_dir)
    return sorted(dirs)


def harden_all(settings) -> list[str]:
    """Tüm hassas klasörleri sertleştirir. Atlanan/başarısız olanların listesini döner."""
    skipped = []
    for d in protected_dirs(settings):
        try:
            harden(d)
        except (OSError, ValueError) as exc:
            skipped.append(f"{d}: {exc}")
    return skipped
