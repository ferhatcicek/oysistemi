"""Web katmanı uçtan uca: iki yönetici, basılı kod + e-posta girişi, kör imza, çerezsiz oy."""
from __future__ import annotations

import base64
import email
import re
import secrets

import pytest
from fastapi.testclient import TestClient

from oysistemi.admin import governance as gov
from oysistemi.auth import totp
from oysistemi.config import Settings
from oysistemi.context import initialise, open_context
from oysistemi.crypto import blind_rsa, keystore
from oysistemi.web.app import create_app
from oysistemi.web.security import ADMIN_COOKIE, unsign

BASE = "http://testserver"


@pytest.fixture(autouse=True)
def _reset_lockouts():
    from oysistemi.auth import admin_auth
    admin_auth._failures.clear()
    admin_auth._last_totp_counter.clear()
    yield
    admin_auth._failures.clear()
    admin_auth._last_totp_counter.clear()


@pytest.fixture
def web(tmp_path, clock):
    s = Settings(db_path=tmp_path / "db" / "oys.db", master_key_path=tmp_path / "k" / "master.key",
                 checkpoint_path=tmp_path / "cp.jsonl", rsa_bits=2048,
                 outbox_dir=tmp_path / "outbox", cookie_secure=False)
    initialise(s)
    ctx = open_context(s)
    gov.bootstrap_admins(ctx, [("ayse", "ayse", "parola-ayse-123"),
                               ("mehmet", "mehmet", "parola-mehmet-123")])
    app = create_app(s, clock=clock)
    app.state.clock = clock
    yield app, ctx, s
    ctx.close()


def admin_client(app, username: str, password: str) -> TestClient:
    c = TestClient(app, base_url=BASE)
    r = c.post("/admin/login", data={"username": username, "password": password},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin/totp"
    sess = unsign(app.state.keys.session, "admin", c.cookies.get(ADMIN_COOKIE))
    assert c.get("/admin/totp").status_code == 200
    code = totp.now_code(sess["enroll"], at=app.state.clock.now())
    r = c.post("/admin/totp", data={"code": code}, follow_redirects=False)
    assert r.headers["location"] == "/admin"
    return c


def csrf_of(client: TestClient) -> str:
    return unsign(client.app.state.keys.session, "admin", client.cookies.get(ADMIN_COOKIE))["csrf"]


def post(client: TestClient, url: str, data: dict | None = None, **kw):
    return client.post(url, data={"csrf": csrf_of(client), **(data or {})}, **kw)


def approve_all(ctx, approver: TestClient) -> None:
    for (rid,) in ctx.conn.execute("SELECT id FROM change_requests WHERE status = 'pending'"):
        r = post(approver, f"/admin/requests/{rid}", {"decision": "approve"})
        assert r.status_code == 200, r.text


def vote_via_http(app, voter: TestClient, eid: str, ballot: dict) -> str:
    """Tarayıcının yaptığını yapar: körle → /issue (çerezli) → çöz → /cast (çerezsiz)."""
    page = voter.get(f"/e/{eid}/vote")
    assert page.status_code == 200
    csrf = re.search(r'data-csrf="([^"]+)"', page.text).group(1)
    pk_json = voter.get(f"/api/e/{eid}/key").json()
    pk = keystore.load_public_pem(
        b"-----BEGIN PUBLIC KEY-----\n" + pk_json["spki"].encode() + b"\n-----END PUBLIC KEY-----")
    token = blind_rsa.prepare(secrets.token_bytes(32))
    blinded, inv = blind_rsa.blind(pk, token)
    r = voter.post(f"/api/e/{eid}/issue", json={"blinded": base64.b64encode(blinded).decode()},
                   headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    sig = blind_rsa.finalize(pk, token, base64.b64decode(r.json()["blind_sig"]), inv)
    voter.post("/voter/logout")
    anon = TestClient(app, base_url=BASE)  # çerezsiz, yeni istemci
    r = anon.post(f"/api/e/{eid}/cast", json={"token": base64.b64encode(token).decode(),
                                              "sig": base64.b64encode(sig).decode(),
                                              "ballot": ballot})
    assert r.status_code == 200, r.text
    return r.json()["receipt"]


def test_full_election_over_http(web):
    app, ctx, settings = web
    ayse = admin_client(app, "ayse", "parola-ayse-123")
    mehmet = admin_client(app, "mehmet", "parola-mehmet-123")

    # Seçmenler: öneri + onay
    r = post(ayse, "/admin/voters", {"lines": "1001; Ali Veli; ali@example.org\n"
                                              "1002; Ayşe Fatma\n1003; Can Demir; can@example.org"})
    assert "Öneri oluşturuldu" in r.text
    # Öneren kendisi onaylayamaz
    (rid,) = ctx.conn.execute("SELECT id FROM change_requests WHERE status='pending'").fetchone()
    r = post(ayse, f"/admin/requests/{rid}", {"decision": "approve"})
    assert "proposer cannot approve" in r.text
    approve_all(ctx, mehmet)
    assert ctx.conn.execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 3

    # Oylama: taslak → liste → açılış
    r = post(ayse, "/admin/elections/new", {
        "id": "baskan", "title": "Başkan seçimi", "ballot_type": "single",
        "options": "Zeynep\nOsman", "min_turnout": "2", "auth_printed_code": "on",
        "closes_at": "2026-10-15T14:00",  # İstanbul saati = START + 1 saat
        "auth_email_otp": "on", "randomize_order": "on"})
    assert "Taslak oluşturuldu" in r.text
    post(ayse, "/admin/elections/baskan/roll", {"voter": ["1001", "1002", "1003"]})
    approve_all(ctx, mehmet)
    post(ayse, "/admin/elections/baskan/open")
    dash = mehmet.get("/admin").text  # onaylayan neyi onayladığını görür
    assert "Başkan seçimi" in dash and "Zeynep, Osman" in dash and "3 seçmen" in dash
    approve_all(ctx, mehmet)
    assert "Açık" in ayse.get("/admin/elections/baskan").text

    # Basılı kodlar
    r = post(ayse, "/admin/elections/baskan/codes")
    codes = dict(re.findall(r'<span class="code">([^<]+)</span></td>\s*<td>Giriş kodu<br>'
                            r'<span class="code">([^<]+)</span>', r.text))
    assert set(codes) == {"1001", "1002", "1003"}

    # Seçmen 1: basılı kod
    v1 = TestClient(app, base_url=BASE)
    r = v1.post("/e/baskan/login", data={"voter_id": "1001", "code": codes["1001"].lower(),
                                         "method": "printed_code"}, follow_redirects=False)
    assert r.headers["location"] == "/e/baskan/vote"
    receipt1 = vote_via_http(app, v1, "baskan", {"choice": "Zeynep"})

    # Aynı seçmen tekrar girip ikinci oy hakkı alamaz
    v1b = TestClient(app, base_url=BASE)
    v1b.post("/e/baskan/login", data={"voter_id": "1001", "code": codes["1001"],
                                      "method": "printed_code"})
    with pytest.raises(AssertionError):
        vote_via_http(app, v1b, "baskan", {"choice": "Osman"})

    # Seçmen 3: e-posta OTP
    v3 = TestClient(app, base_url=BASE)
    r = v3.post("/e/baskan/email", data={"voter_id": "1003"})
    assert "kod gönderildi" in r.text
    (eml,) = list(settings.outbox_dir.glob("*.eml"))
    body = email.message_from_bytes(eml.read_bytes()).get_payload(decode=True).decode()
    code = re.search(r"giriş kodunuz: (\d{8})", body).group(1)
    r = v3.post("/e/baskan/login", data={"voter_id": "1003", "code": code, "method": "email_otp"},
                follow_redirects=False)
    assert r.headers["location"] == "/e/baskan/vote"
    vote_via_http(app, v3, "baskan", {"choice": "Zeynep"})

    # Kapanış ve sonuç
    # Bitişten önce: kapanış onaylansa bile uygulanmaz, sonuç ve katılım görünmez
    post(ayse, "/admin/elections/baskan/close")
    (rid,) = ctx.conn.execute("SELECT id FROM change_requests WHERE status='pending'").fetchone()
    r = post(mehmet, f"/admin/requests/{rid}", {"decision": "approve"})
    assert "scheduled end" in r.text
    assert TestClient(app, base_url=BASE).get("/e/baskan/results").status_code == 404
    page = ayse.get("/admin/elections/baskan").text
    assert "Oy hakkı alan" not in page and "Sandıktaki oy" not in page
    audit = ayse.get("/admin/audit").text
    assert "credential_issued" not in audit and "voter_login" not in audit
    # Bitiş geçtikten sonra aynı öneri onaylanınca kapanır
    app.state.clock.advance(3601)
    r = post(mehmet, f"/admin/requests/{rid}", {"decision": "approve"})
    approve_all(ctx, mehmet)
    res = TestClient(app, base_url=BASE).get("/e/baskan/results")
    assert res.status_code == 200 and "Zeynep" in res.text
    board = TestClient(app, base_url=BASE).get("/api/e/baskan/bulletin.json").json()
    assert board["result"]["tally"]["counts"] == {"Zeynep": 2, "Osman": 0}
    assert receipt1 in board["receipts"]

    # Bütünlük: kritik bulgu yok (test anahtarı 'file' modunda → yalnızca uyarı beklenir)
    page = ayse.get("/admin/verify").text
    assert "kritik bulgu" not in page.lower() or "Kritik bulgu yok" in page
    assert "master key is stored unencrypted" in page


def test_security_controls(web):
    app, ctx, _ = web
    anon = TestClient(app, base_url=BASE)
    # Yönetici sayfaları girişsiz açılmaz
    assert anon.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
    # Parola doğru ama TOTP aşaması tamamlanmadan panel açılmaz
    half = TestClient(app, base_url=BASE)
    half.post("/admin/login", data={"username": "ayse", "password": "parola-ayse-123"},
              follow_redirects=False)
    assert half.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
    # Hatalı parola
    r = anon.post("/admin/login", data={"username": "ayse", "password": "yanlis"})
    assert "hatalı" in r.text
    # Başka siteden gelen POST reddedilir
    r = anon.post("/admin/login", data={"username": "ayse", "password": "x"},
                  headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = anon.post("/admin/login", data={"username": "ayse", "password": "x"},
                  headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    # Regresyon: gerçek tarayıcı aynı siteden form gönderirken Origin "null" olabilir
    r = anon.post("/admin/login", data={"username": "ayse", "password": "x"},
                  headers={"Sec-Fetch-Site": "same-origin", "Origin": "null"})
    assert r.status_code == 200 and "hatalı" in r.text
    # Güvenlik başlıkları
    h = anon.get("/").headers
    assert "script-src 'self'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"

    ayse = admin_client(app, "ayse", "parola-ayse-123")
    # CSRF belirteci olmadan form işlenmez
    r = ayse.post("/admin/voters", data={"lines": "9; X"})
    assert "Oturum doğrulaması başarısız" in r.text
    assert ctx.conn.execute("SELECT COUNT(*) FROM change_requests").fetchone()[0] == 0


def test_issue_requires_voter_session_and_cast_rejects_forgery(web):
    app, ctx, _ = web
    ayse = admin_client(app, "ayse", "parola-ayse-123")
    mehmet = admin_client(app, "mehmet", "parola-mehmet-123")
    post(ayse, "/admin/voters", {"lines": "1; A\n2; B"})
    approve_all(ctx, mehmet)
    post(ayse, "/admin/elections/new", {"id": "k", "title": "Karar", "ballot_type": "yes_no",
                                        "min_turnout": "1", "auth_printed_code": "on",
                                        "closes_at": "2026-10-15T14:00"})
    post(ayse, "/admin/elections/k/roll", {"voter": ["1", "2"]})
    approve_all(ctx, mehmet)
    post(ayse, "/admin/elections/k/open")
    approve_all(ctx, mehmet)

    anon = TestClient(app, base_url=BASE)
    r = anon.post("/api/e/k/issue", json={"blinded": base64.b64encode(b"x" * 256).decode()})
    assert r.status_code == 401
    r = anon.post("/api/e/k/cast", json={"token": base64.b64encode(b"t" * 64).decode(),
                                         "sig": base64.b64encode(b"s" * 256).decode(),
                                         "ballot": {"choice": "evet"}})
    assert r.status_code == 400
    # Yanlış kodla giriş
    r = anon.post("/e/k/login", data={"voter_id": "1", "code": "AAAA-BBBB-CCCC",
                                      "method": "printed_code"}, follow_redirects=False)
    assert "err=code" in r.headers["location"]


def test_admin_totp_code_cannot_be_replayed(web):
    app, _, _ = web
    c = TestClient(app, base_url=BASE)
    c.post("/admin/login", data={"username": "ayse", "password": "parola-ayse-123"},
           follow_redirects=False)
    secret = unsign(app.state.keys.session, "admin", c.cookies.get(ADMIN_COOKIE))["enroll"]
    code = totp.now_code(secret, at=app.state.clock.now())
    assert c.post("/admin/totp", data={"code": code}, follow_redirects=False).headers[
        "location"] == "/admin"

    def login_with(code):
        x = TestClient(app, base_url=BASE)
        x.post("/admin/login", data={"username": "ayse", "password": "parola-ayse-123"},
               follow_redirects=False)
        return x.post("/admin/totp", data={"code": code}, follow_redirects=False)

    assert login_with(code).headers["location"] == "/admin"          # ilk kullanım
    assert "err=" in login_with(code).headers["location"]            # aynı kod tekrar: red


def test_admin_lockout(web):
    app, ctx, _ = web
    c = TestClient(app, base_url=BASE)
    for _ in range(5):
        c.post("/admin/login", data={"username": "mehmet", "password": "yanlis"})
    r = c.post("/admin/login", data={"username": "mehmet", "password": "parola-mehmet-123"})
    assert "kilitlendi" in r.text


def test_admin_add_requires_both_enrollment_parts(web):
    """Regresyon (güvenlik incelemesi): tek bir yönetici yeni yönetici hesabını ele geçiremez.

    Eski akışta öneren parolayı belirliyor, onaydan sonra hesaba girip TOTP'yi kendi telefonuna
    kaydedebiliyordu (iki kişi kuralının tek kişiyle aşılması).
    """
    import re as _re
    app, ctx, _ = web
    ayse = admin_client(app, "ayse", "parola-ayse-123")
    mehmet = admin_client(app, "mehmet", "parola-mehmet-123")

    r = post(ayse, "/admin/admins", {"username": "zeynep", "role": "admin"})
    part_a = _re.search(r'<p class="code">([^<]+)</p>', r.text).group(1)
    (rid,) = ctx.conn.execute("SELECT id FROM change_requests WHERE status='pending'").fetchone()
    # Öneri yükünde A parçasının kendisi yok, yalnızca özeti
    from oysistemi.admin import governance as _gov
    payload = _gov.request_payload(ctx, ctx.conn.execute(
        "SELECT * FROM change_requests WHERE id = ?", (rid,)).fetchone())
    assert part_a not in str(payload) and payload["enroll_a_hash"].startswith("$argon2")

    r = post(mehmet, f"/admin/requests/{rid}", {"decision": "approve"})
    part_b = _re.search(r'<p class="code">([^<]+)</p>', r.text).group(1)
    assert part_a != part_b

    # SALDIRI 1: öneren, yeni hesaba herhangi bir parolayla giremez (hesap parolasız)
    for guess in ("parola-ayse-123", part_a, ""):
        x = TestClient(app, base_url=BASE)
        r = x.post("/admin/login", data={"username": "zeynep", "password": guess or "x"},
                   follow_redirects=False)
        assert "totp" not in r.headers.get("location", ""), guess

    # SALDIRI 2: tek parçayla etkinleştirme reddedilir (öneren yalnızca A'yı bilir)
    anon = TestClient(app, base_url=BASE)
    r = anon.post("/admin/enroll", data={"username": "zeynep", "part_a": part_a,
                                         "part_b": part_a, "password": "ele-gecirme-123",
                                         "password2": "ele-gecirme-123"}, follow_redirects=False)
    assert "err=" in r.headers["location"]

    # Meşru akış: iki parça + kendi parolası → giriş → kendi TOTP'si
    r = anon.post("/admin/enroll", data={"username": "zeynep", "part_a": part_a.upper(),
                                         "part_b": part_b, "password": "zeynep-kendi-parolasi",
                                         "password2": "zeynep-kendi-parolasi"},
                  follow_redirects=False)
    assert r.headers["location"].startswith("/admin/login")
    zeynep = admin_client(app, "zeynep", "zeynep-kendi-parolasi")
    assert zeynep.get("/admin").status_code == 200

    # Aynı kodlar ikinci kez kullanılamaz
    r = anon.post("/admin/enroll", data={"username": "zeynep", "part_a": part_a,
                                         "part_b": part_b, "password": "ikinci-deneme-123",
                                         "password2": "ikinci-deneme-123"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_totp_enrollment_page_shows_scannable_qr(web):
    """İlk giriş karekodu: doğru otpauth adresi, CSP uyumu, elle giriş yedeği."""
    import segno

    from oysistemi.auth import totp as _totp
    app, _, _ = web
    c = TestClient(app, base_url=BASE)
    c.post("/admin/login", data={"username": "ayse", "password": "parola-ayse-123"},
           follow_redirects=False)
    secret = unsign(app.state.keys.session, "admin", c.cookies.get(ADMIN_COOKIE))["enroll"]
    page = c.get("/admin/totp").text
    uri = _totp.provisioning_uri(secret, "ayse")
    # Sayfadaki SVG, bu otpauth adresi için üretilen karekodun birebir aynısı
    assert _totp.qr_svg(uri) in page
    assert segno.make(uri, error="m").designator  # geçerli bir karekod
    svg = page[page.index("<svg"):page.index("</svg>")]
    assert "<script" not in svg and "style=" not in svg  # CSP: satır içi betik/stil yok
    assert f'href="{uri.replace("&", "&amp;")}"' in page  # "telefonda aç" bağlantısı
    assert _totp.group(secret) in page  # elle giriş yedeği (4'erli gruplar)
