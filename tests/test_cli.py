"""Komut satırı: durum raporu, tekrar çalıştırılabilirlik, anlaşılır hata mesajları."""
from __future__ import annotations

import json

import pytest

from oysistemi import cli
from oysistemi.admin import governance as gov
from oysistemi.context import initialise, open_context


@pytest.fixture
def home(tmp_path, monkeypatch):
    for var in ("OYS_DB", "OYS_MASTER_KEY", "OYS_CHECKPOINTS", "OYS_OUTBOX"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OYS_KEY_PROTECTION", "file")
    monkeypatch.setenv("OYS_TIME_MODE", "system")
    return tmp_path / "kurulum"


def run(home, *args, capsys) -> tuple[int, str, str]:
    code = cli.main(["--home", str(home), *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_status_before_and_after_init(home, capsys):
    code, out, _ = run(home, "status", "--json", capsys=capsys)
    assert code == 0 and json.loads(out)["initialised"] is False

    initialise(cli.Settings.from_env(home))
    code, out, _ = run(home, "status", "--json", capsys=capsys)
    info = json.loads(out)
    assert info["initialised"] and info["key_opens"] and info["admins"] == []


def test_bootstrap_rerun_does_not_ask_for_passwords(home, capsys, monkeypatch):
    """Regresyon: yöneticiler varken parolalar sorulup sonra iz kaydıyla hata veriliyordu."""
    s = cli.Settings.from_env(home)
    initialise(s)
    ctx = open_context(s)
    gov.bootstrap_admins(ctx, [("ferhatcicek", "ferhatcicek", "x" * 12),
                               ("fcicek", "fcicek", "y" * 12)])
    ctx.close()

    def no_prompt(*_a, **_k):
        raise AssertionError("must not prompt for a password")

    monkeypatch.setattr(cli.getpass, "getpass", no_prompt)
    code, out, _ = run(home, "bootstrap-admins", "a:a", "b:b", capsys=capsys)
    assert code == 3 and "ferhatcicek, fcicek" in out

    code, out, _ = run(home, "status", "--json", capsys=capsys)
    assert [a["username"] for a in json.loads(out)["admins"]] == ["ferhatcicek", "fcicek"]


def test_user_errors_are_messages_not_tracebacks(home, capsys, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass",
                        lambda *_a, **_k: pytest.fail("must fail before prompting"))
    code, _, err = run(home, "restore", str(home / "yok.oysbak"), capsys=capsys)
    assert code == 2 and err.startswith("HATA:") and "bulunamadı" in err
    code, _, err = run(home, "key", "recover", str(home / "yok.oyskey"), capsys=capsys)
    assert code == 2 and "kurtarma anahtarı dosyası bulunamadı" in err
