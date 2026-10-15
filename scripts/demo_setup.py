"""Deneme kurulumu: iki yönetici, birkaç seçmen, açık bir oylama ve basılı kodlar.

    python scripts/demo_setup.py demo
    python -m oysistemi.cli --home demo serve --insecure-http

Giriş bilgileri <klasör>/DENEME_GIRIS.txt dosyasına yazılır. YALNIZCA deneme içindir.
"""
from __future__ import annotations

import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from oysistemi.admin import governance as gov  # noqa: E402
from oysistemi.auth import voter_auth  # noqa: E402
from oysistemi.config import Settings  # noqa: E402
from oysistemi.context import configure_clock, initialise, open_context  # noqa: E402
from oysistemi.elections import service  # noqa: E402


def approve(ctx, kind, payload):
    rid = gov.propose(ctx, "ayse", kind, payload)
    gov.decide(ctx, "mehmet", rid, "approve")


def main(home: Path) -> None:
    if home.exists() and any(home.iterdir()):
        sys.exit(f"{home} boş değil; var olan kurulumun üzerine yazılmaz.")
    s = Settings.from_env(home)
    clock = configure_clock(s)
    if clock.assurance == "unverified":
        sys.exit("Zaman sunucularına ulaşılamadı. İnternetsiz deneme için: OYS_TIME_MODE=system")

    def later(seconds: int) -> str:
        return datetime.fromtimestamp(clock.now() + seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    initialise(s)
    ctx = open_context(s)
    pw = {u: secrets.token_urlsafe(12) for u in ("ayse", "mehmet")}
    gov.bootstrap_admins(ctx, [("ayse", "ayse", pw["ayse"]), ("mehmet", "mehmet", pw["mehmet"])])

    approve(ctx, "voters_add", {"voters": [
        {"id": "1001", "display_name": "Ali Yılmaz", "email": "ali@example.org"},
        {"id": "1002", "display_name": "Zeynep Kaya", "email": "zeynep@example.org"},
        {"id": "1003", "display_name": "Can Demir", "email": None},
        {"id": "1004", "display_name": "Elif Şahin", "email": "elif@example.org"},
    ]})
    service.create_election(ctx, "ayse", "yonetim-2026", "Yönetim kurulu seçimi 2026", "multi",
                            {"ballot": {"options": ["Ayten Uslu", "Berk Toprak", "Cem Arslan",
                                                    "Deniz Ak"], "min_choices": 1,
                                        "max_choices": 2},
                             "min_turnout": 2, "closes_at": later(2 * 3600)})
    approve(ctx, "roll_add", {"election_id": "yonetim-2026",
                              "voter_ids": ["1001", "1002", "1003", "1004"]})
    approve(ctx, "election_open", {"election_id": "yonetim-2026"})
    codes = voter_auth.generate_printed_codes(ctx, "ayse", "yonetim-2026")

    service.create_election(ctx, "ayse", "butce", "2027 bütçesinin onayı", "yes_no",
                            {"ballot": {"allow_blank": False}, "min_turnout": 2,
                             "closes_at": later(7 * 86400)})
    ctx.close()

    lines = ["DENEME KURULUMU — gerçek oylamada kullanmayın", "",
             "Yönetici paneli: http://127.0.0.1:8000/admin",
             "(ilk girişte kimlik doğrulayıcı uygulama kurulumu istenir)", ""]
    lines += [f"  {u} / {p}" for u, p in pw.items()]
    lines += ["", "Oy verme: http://127.0.0.1:8000/e/yonetim-2026 (2 saat açık kalır)", ""]
    lines += [f"  seçmen {c['voter_id']} ({c['display_name']}): {c['code']}" for c in codes]
    lines += ["", "E-posta kodları SMTP ayarlanmadığı için outbox/ klasörüne .eml olarak düşer."]
    (home / "DENEME_GIRIS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Hazır. Giriş bilgileri: {home / 'DENEME_GIRIS.txt'}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "demo"))
