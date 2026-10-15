"""Yönetim komut satırı: kurulum, ilk yöneticiler, bütünlük doğrulama, checkpoint."""
from __future__ import annotations

import argparse
import dataclasses
import getpass
import sys
from pathlib import Path

from .admin import governance as gov
from .audit import checkpoint, verifier
from .config import Settings
from .context import check_clock_against_db, configure_clock, initialise, open_context


def _ask_new_passphrase(prompt: str, env: str | None = None) -> str:
    import os
    if env:
        value = os.environ.get(env, "")
        if len(value) < 12:
            raise SystemExit(f"{env} must contain a passphrase of at least 12 characters")
        return value
    while True:
        p1 = getpass.getpass(f"{prompt} (en az 12 karakter): ")
        if len(p1) < 12:
            print("En az 12 karakter olmalı.")
            continue
        if getpass.getpass("Tekrar: ") == p1:
            return p1
        print("Eşleşmedi, tekrar deneyin.")


def _cmd_init(s: Settings, args: argparse.Namespace) -> int:
    print(f"Ana anahtar koruması: {s.key_protection}")
    passphrase = (_ask_new_passphrase("Ana anahtar parolası", args.passphrase_env)
                  if s.key_protection == "passphrase" else None)
    print("Kurtarma anahtarı: sunucu bozulursa veya başka bilgisayara taşınırsa verileri açmanın "
          "TEK yolu. Parolasını güvenli bir yere yazın.")
    recovery = _ask_new_passphrase("Kurtarma anahtarı parolası", args.recovery_passphrase_env)
    initialise(s, recovery_passphrase=recovery, passphrase=passphrase)
    print(f"veritabanı:        {s.db_path}")
    print(f"ana anahtar:       {s.master_key_path}  ({s.key_protection})")
    print(f"KURTARMA ANAHTARI: {s.recovery_key_path}")
    print("  → Bu dosyayı şimdi bir USB belleğe / kasaya kopyalayın ve SUNUCUDAN SİLİN.")
    return 0


def _cmd_key(s: Settings, args: argparse.Namespace) -> int:
    from .crypto import keyfile
    if args.action == "status":
        print(f"koruma: {s.key_protection_in_use()}")
        on_server = s.recovery_key_path.exists()
        print("kurtarma anahtarı sunucuda: "
              + ("EVET — çevrimdışına taşıyın" if on_server else "hayır"))
        return 0
    if args.action == "export-recovery":
        master, _ = keyfile.decode(s.master_key_path.read_bytes(), lambda: getpass.getpass(
            "Ana anahtar parolası: "))
        out = Path(args.file or s.recovery_key_path)
        keyfile.write_new(out, keyfile.encode(master, "passphrase",
                                              _ask_new_passphrase("Kurtarma anahtarı parolası")))
        print(f"kurtarma anahtarı yazıldı: {out}")
        return 0
    if args.action == "protect":
        master, old = keyfile.decode(s.master_key_path.read_bytes(), lambda: getpass.getpass(
            "Mevcut ana anahtar parolası: "))
        new = args.mode
        passphrase = (_ask_new_passphrase("Yeni ana anahtar parolası")
                      if new == "passphrase" else None)
        keyfile.replace(s.master_key_path, keyfile.encode(master, new, passphrase))
        print(f"ana anahtar koruması: {old} → {new}")
        return 0
    if args.action == "recover":
        if s.master_key_path.exists():
            raise SystemExit(f"ana anahtar zaten var: {s.master_key_path}")
        rec_file = Path(args.file or s.recovery_key_path)
        import os
        master, _ = keyfile.decode(rec_file.read_bytes(), lambda: os.environ.get(
            "OYS_RECOVERY_PASSPHRASE") or getpass.getpass("Kurtarma anahtarı parolası: "))
        from . import osprotect
        osprotect.harden(s.master_key_path.parent)
        passphrase = (_ask_new_passphrase("Yeni ana anahtar parolası")
                      if s.key_protection == "passphrase" else None)
        keyfile.write_new(s.master_key_path, keyfile.encode(master, s.key_protection, passphrase))
        print(f"ana anahtar bu hesap/makine için yeniden oluşturuldu ({s.key_protection}).")
        return 0
    return 2


def _cmd_backup(s: Settings, args: argparse.Namespace) -> int:
    import os

    from . import backup
    # Zamanlanmış görev için: OYS_BACKUP_PASSPHRASE tanımlıysa sormadan kullanılır.
    env = "OYS_BACKUP_PASSPHRASE" if os.environ.get("OYS_BACKUP_PASSPHRASE") else None
    out = Path(args.file.replace("{tarih}", __import__("datetime").datetime.now()
                                 .strftime("%Y%m%d-%H%M%S")))
    size = backup.create(s, out, _ask_new_passphrase("Yedek parolası", env))
    args.file = str(out)
    print(f"şifreli yedek yazıldı: {args.file} ({size // 1024} KB veritabanı)")
    print("Not: yedeği açmak için ayrıca KURTARMA ANAHTARI gerekir.")
    return 0


def _cmd_restore(s: Settings, args: argparse.Namespace) -> int:
    from . import backup, osprotect
    for d in osprotect.protected_dirs(s):
        osprotect.harden(d)
    import os
    backup.restore(s, Path(args.file), os.environ.get("OYS_BACKUP_PASSPHRASE")
                   or getpass.getpass("Yedek parolası: "))
    print(f"geri yüklendi: {s.db_path}")
    if not s.master_key_path.exists():
        print("Şimdi ana anahtarı kurtarın:  oysistemi key recover <KURTARMA_DOSYASI>")
    return 0


def _cmd_harden(s: Settings, _: argparse.Namespace) -> int:
    from . import osprotect
    failed = osprotect.harden_all(s)
    for f in failed:
        print(f"ATLANDI: {f}")
    problems = osprotect.check(osprotect.protected_dirs(s))
    for p in problems:
        print(f"SORUN: {p}")
    print("izinler kilitlendi." if not problems and not failed else "")
    return 1 if problems or failed else 0


def _cmd_bootstrap(s: Settings, args: argparse.Namespace) -> int:
    admins = []
    for spec in args.admins:
        admin_id, _, username = spec.partition(":")
        pw = getpass.getpass(f"{username or admin_id} parolası: ")
        if len(pw) < 12:
            print("parola en az 12 karakter olmalı", file=sys.stderr)
            return 2
        admins.append((admin_id, username or admin_id, pw))
    ctx = open_context(s)
    try:
        gov.bootstrap_admins(ctx, admins)
    finally:
        ctx.close()
    print(f"{len(admins)} yönetici oluşturuldu.")
    return 0


def _cmd_verify(s: Settings, _: argparse.Namespace) -> int:
    ctx = open_context(s, allow_locked=True)
    try:
        findings = verifier.verify(ctx.conn, ctx.keys, s.checkpoint_path, s)
    finally:
        ctx.close()
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.code:18} {f.detail}")
    critical = [f for f in findings if f.severity == "critical"]
    print(f"\n{len(critical)} kritik, {len(findings) - len(critical)} uyarı.")
    return 1 if critical else 0


def _cmd_checkpoint(s: Settings, _: argparse.Namespace) -> int:
    ctx = open_context(s)
    try:
        snap = checkpoint.take(ctx.conn, ctx.keys.checkpoint, s.checkpoint_path)
    finally:
        ctx.close()
    print(f"checkpoint @ audit seq {snap['audit_seq']} → {s.checkpoint_path}")
    return 0


def _cmd_tick(s: Settings, _: argparse.Namespace) -> int:
    """Cron için: bitiş zamanı gelmiş oylamaları kapatır (sunucu zamanlayıcısına ek güvence)."""
    from .elections.service import close_due_elections
    ctx = open_context(s)
    try:
        closed = close_due_elections(ctx)
    finally:
        ctx.close()
    for eid in closed:
        print(f"kapatıldı ve sayıldı: {eid}")
    return 0


def _cmd_clock(s: Settings, _: argparse.Namespace) -> int:
    from .timekeeping import get_clock
    c = get_clock()
    print(f"mod: {c.mode}  güvence: {c.assurance}  güvenilir zaman: {c.iso()}")
    print(f"sistem saati sapması: {c.check_jump():+.1f} sn")
    for a in c.alarms:
        print(f"  [{a.kind}] {a.detail}")
    return 0 if c.assurance != "unverified" and not any(
        a.kind in ("clock_rollback", "system_clock_jump") for a in c.alarms) else 1


def _cmd_serve(s: Settings, args: argparse.Namespace) -> int:
    import uvicorn

    from .web.app import create_app

    if args.insecure_http:
        print("UYARI: düz HTTP modu — yalnızca yerel test için. Üretimde HTTPS kullanın.")
        s = dataclasses.replace(s, cookie_secure=False)
    from . import osprotect
    for f in osprotect.harden_all(s):  # her açılışta izin kaymasını düzelt
        print(f"UYARI: izinler kilitlenemedi: {f}")
    # access_log=False: oy gönderimlerinin IP/zaman bilgisi hiçbir yerde kalmamalı.
    uvicorn.run(create_app(s, scheduler=True), host=args.host, port=args.port, access_log=False,
                proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips,
                server_header=False)
    return 0


def _fix_console() -> None:
    """Windows: çıktı bir dosyaya/boruya yönlendirildiğinde Türkçe karakterler bozulmasın."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _fix_console()
    from .osprotect import restrict_umask
    restrict_umask()
    p = argparse.ArgumentParser(prog="oysistemi")
    p.add_argument("--home", type=Path, help="kurulum klasörü (varsayılan: OYS_HOME veya .)")
    sub = p.add_subparsers(dest="cmd", required=True)
    ini = sub.add_parser("init", help="yeni kurulum (korumalı ana anahtar + kurtarma + şema)")
    ini.add_argument("--recovery-passphrase-env", metavar="DEĞİŞKEN",
                     help="kurtarma parolasını bu ortam değişkeninden al (otomasyon)")
    ini.add_argument("--passphrase-env", metavar="DEĞİŞKEN",
                     help="passphrase modunda ana anahtar parolası için ortam değişkeni")
    k = sub.add_parser("key", help="ana anahtar yönetimi")
    k.add_argument("action", choices=["status", "protect", "export-recovery", "recover"])
    k.add_argument("file", nargs="?", help="kurtarma dosyası (recover/export-recovery)")
    k.add_argument("--mode", choices=["dpapi", "passphrase", "file"], default="dpapi")
    bk = sub.add_parser("backup", help="şifreli yedek al")
    bk.add_argument("file")
    rs = sub.add_parser("restore", help="şifreli yedekten geri yükle")
    rs.add_argument("file")
    sub.add_parser("harden", help="klasör izinlerini kilitle ve denetle")
    b = sub.add_parser("bootstrap-admins", help="ilk yöneticileri oluştur (en az 2)")
    b.add_argument("admins", nargs="+", metavar="ID:KULLANICI")
    sub.add_parser("verify", help="tüm bütünlük kontrollerini çalıştır")
    sub.add_parser("checkpoint", help="harici checkpoint yaz")
    sub.add_parser("tick", help="zamanı gelen oylamaları kapat (cron)")
    sub.add_parser("clock", help="güvenilir saat durumunu göster")
    sv = sub.add_parser("serve", help="web sunucusunu başlat")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--forwarded-allow-ips", default="127.0.0.1",
                    help="ters vekil (Caddy/nginx) adresleri")
    sv.add_argument("--insecure-http", action="store_true",
                    help="çerezlerde Secure bayrağını kapat (yalnızca yerel test)")
    args = p.parse_args(argv)
    handlers = {"init": _cmd_init, "bootstrap-admins": _cmd_bootstrap,
                "verify": _cmd_verify, "checkpoint": _cmd_checkpoint, "serve": _cmd_serve,
                "tick": _cmd_tick, "clock": _cmd_clock, "key": _cmd_key,
                "backup": _cmd_backup, "restore": _cmd_restore, "harden": _cmd_harden}
    settings = Settings.from_env(args.home)
    if args.cmd in ("verify", "tick", "clock", "checkpoint", "bootstrap-admins"):
        configure_clock(settings)
        check_clock_against_db(settings)
    return handlers[args.cmd](settings, args)


if __name__ == "__main__":
    raise SystemExit(main())
