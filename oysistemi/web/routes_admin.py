"""Yönetici paneli. Her değişiklik governance (iki kişi kuralı) üzerinden gider."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response
from markupsafe import Markup
from starlette.datastructures import FormData

from ..admin import enrollment
from ..admin import governance as gov
from ..audit import chain, checkpoint, verifier
from ..auth import admin_auth, totp, voter_auth
from ..context import Context
from ..crypto import rowmac
from ..db.connection import IntegrityError
from ..elections import ballot_types, service
from ..elections.ballot_types import ConfigError
from ..elections.config import AUTH_METHODS
from .app import Redirect, get_ctx, render, to_utc_iso
from .security import ADMIN_COOKIE, ADMIN_TTL, new_csrf, set_cookie, sign, unsign

router = APIRouter(prefix="/admin")

DOMAIN_ERRORS = (gov.GovernanceError, enrollment.EnrollmentError, service.ElectionStateError,
                 ConfigError, voter_auth.VoterAuthError, admin_auth.AdminAuthError, LookupError)

BALLOT_LABELS = {
    "single": "Tek seçim", "yes_no": "Evet / Hayır / Çekimser", "multi": "Çoklu seçim",
    "approval": "Onay oylaması", "borda": "Sıralı — Borda", "ranked_irv": "Sıralı — IRV",
}
KIND_LABELS = {
    "voter_add": "Seçmen ekle", "voters_add": "Toplu seçmen ekle",
    "voter_disable": "Seçmeni devre dışı bırak", "roll_add": "Seçmen listesine ekle",
    "roll_remove": "Seçmen listesinden çıkar", "admin_add": "Yönetici ekle",
    "election_open": "Oylamayı aç", "election_close": "Oylamayı kapat ve say",
}


def _session(request: Request) -> dict[str, Any] | None:
    return unsign(request.app.state.keys.session, "admin", request.cookies.get(ADMIN_COOKIE))


def _set_session(request: Request, resp: Response, data: dict[str, Any]) -> None:
    set_cookie(resp, ADMIN_COOKIE, sign(request.app.state.keys.session, "admin", data, ADMIN_TTL),
               ADMIN_TTL, request.app.state.settings.cookie_secure)


def _admin(request: Request, ctx: Context) -> tuple[dict[str, Any], dict[str, Any]]:
    """Tam (parola + TOTP) oturumu ister. Dönüş: (yönetici satırı, oturum)."""
    sess = _session(request)
    if not sess or sess.get("stage") != "full":
        raise Redirect("/admin/login")
    row = ctx.conn.execute("SELECT * FROM admins WHERE id = ?", (sess["aid"],)).fetchone()
    if row is None:
        raise Redirect("/admin/login")
    row = dict(row)
    if not rowmac.verify(ctx.keys.row_mac, "admins", row):
        raise IntegrityError("admin row MAC invalid")
    return row, sess


async def _form(request: Request, sess: dict[str, Any]) -> FormData:
    form = await request.form()
    if form.get("csrf") != sess.get("csrf"):
        raise Redirect("/admin?err=" + "Oturum doğrulaması başarısız, tekrar deneyin.")
    return form


def _go(url: str, msg: str | None = None, err: str | None = None) -> Redirect:
    from urllib.parse import urlencode
    q = urlencode({k: v for k, v in (("msg", msg), ("err", err)) if v})
    return Redirect(f"{url}?{q}" if q else url)


def _page(request: Request, name: str, admin: dict[str, Any], sess: dict[str, Any], **kw):
    return render(request, name, admin=admin, csrf=sess["csrf"],
                  tz=request.app.state.settings.timezone,
                  msg=request.query_params.get("msg"), err=request.query_params.get("err"),
                  kinds=KIND_LABELS, ballot_labels=BALLOT_LABELS, **kw)


# ───────────────────────── Giriş ─────────────────────────

@router.get("/login")
def login_page(request: Request):
    return render(request, "admin/login.html", err=request.query_params.get("err"))


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          ctx: Context = Depends(get_ctx)):
    if not request.app.state.limiter.allow(f"admin-login:{request.client.host}", 20, 600):
        raise _go("/admin/login", err="Çok fazla deneme. Biraz sonra tekrar deneyin.")
    try:
        admin = admin_auth.check_password(ctx, username, password)
    except admin_auth.AdminAuthError:
        raise _go("/admin/login", err="Hesap geçici olarak kilitlendi.") from None
    if admin is None:
        raise _go("/admin/login", err="Kullanıcı adı veya parola hatalı.")
    data: dict[str, Any] = {"aid": admin["id"], "stage": "password"}
    if admin["totp_secret_enc"] is None:
        data["enroll"] = totp.generate_secret()
    resp = Response(status_code=303, headers={"Location": "/admin/totp"})
    _set_session(request, resp, data)
    return resp


@router.get("/totp")
def totp_page(request: Request, ctx: Context = Depends(get_ctx)):
    sess = _session(request)
    if not sess or sess.get("stage") != "password":
        raise Redirect("/admin/login")
    admin = ctx.conn.execute("SELECT username FROM admins WHERE id = ?", (sess["aid"],)).fetchone()
    secret = sess.get("enroll")
    uri = totp.provisioning_uri(secret, admin["username"]) if secret else None
    # Markup güvenli: SVG'yi segno üretir; içinde yalnızca sayısal çizim yolları ve sabit
    # başlık vardır, kullanıcıdan gelen hiçbir metin SVG'ye yazılmaz.
    qr = Markup(totp.qr_svg(uri)) if uri else None  # noqa: S704  # nosec B704
    return render(request, "admin/totp.html", enroll=secret, uri=uri, qr=qr,
                  grouped=totp.group(secret) if secret else None,
                  username=admin["username"], err=request.query_params.get("err"))


@router.post("/totp")
def totp_submit(request: Request, code: str = Form(...), ctx: Context = Depends(get_ctx)):
    sess = _session(request)
    if not sess or sess.get("stage") != "password":
        raise Redirect("/admin/login")
    try:
        if sess.get("enroll"):
            ok = admin_auth.enroll_totp(ctx, sess["aid"], sess["enroll"], code)
        else:
            row = dict(ctx.conn.execute("SELECT * FROM admins WHERE id = ?",
                                        (sess["aid"],)).fetchone())
            ok = admin_auth.check_totp(ctx, row, code)
    except admin_auth.AdminAuthError:
        raise _go("/admin/login", err="Hesap geçici olarak kilitlendi.") from None
    if not ok:
        raise _go("/admin/totp", err="Kod hatalı.")
    resp = Response(status_code=303, headers={"Location": "/admin"})
    _set_session(request, resp, {"aid": sess["aid"], "stage": "full", "csrf": new_csrf()})
    return resp


@router.post("/logout")
def logout():
    resp = Response(status_code=303, headers={"Location": "/admin/login"})
    resp.delete_cookie(ADMIN_COOKIE, path="/")
    return resp


# ───────────────────────── Pano ve onaylar ─────────────────────────

def _requests(ctx: Context, where: str, limit: int = 50) -> list[dict[str, Any]]:
    rows = ctx.conn.execute(
        f"SELECT cr.*, a.username AS proposer FROM change_requests cr "
        f"JOIN admins a ON a.id = cr.proposed_by WHERE {where} "
        f"ORDER BY cr.created_at DESC LIMIT {int(limit)}").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["payload_obj"] = gov.request_payload(ctx, d)
        d["deciders"] = [x[0] for x in ctx.conn.execute(
            "SELECT a.username || ' (' || ap.decision || ')' FROM approvals ap "
            "JOIN admins a ON a.id = ap.admin_id WHERE ap.request_id = ?", (d["id"],))]
        d["decided_by_me"] = False
        out.append(d)
    return out


@router.get("")
def dashboard(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    pending = _requests(ctx, "cr.status = 'pending'")
    for p in pending:
        p["decided_by_me"] = bool(ctx.conn.execute(
            "SELECT 1 FROM approvals WHERE request_id = ? AND admin_id = ?",
            (p["id"], admin["id"])).fetchone())
    recent = _requests(ctx, "cr.status <> 'pending'", 15)
    elections = ctx.conn.execute("SELECT id, title, status, ballot_type FROM elections "
                                 "ORDER BY rowid DESC").fetchall()
    return _page(request, "admin/dashboard.html", admin, sess, pending=pending, recent=recent,
                 elections=elections)


@router.post("/requests/{request_id}")
async def decide(request: Request, request_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    try:
        status = gov.decide(ctx, admin["id"], request_id, str(form.get("decision")))
    except DOMAIN_ERRORS as exc:
        raise _go("/admin", err=f"İşlem uygulanamadı: {exc}") from None
    if "enroll_b" in ctx.outputs:  # yalnızca bu onaylayana, bir kez
        out = ctx.outputs.pop("enroll_b")
        return _page(request, "admin/enroll_part.html", admin, sess, part_name="B",
                     username=out["username"], part=out["part"])
    text = {"applied": "Onaylandı ve uygulandı.", "rejected": "Öneri reddedildi.",
            "pending": "Onayınız kaydedildi; başka onay bekleniyor."}[status]
    raise _go("/admin", msg=text)


def _propose(ctx: Context, admin: dict[str, Any], kind: str, payload: dict[str, Any],
             back: str) -> Redirect:
    try:
        gov.propose(ctx, admin["id"], kind, payload)
    except DOMAIN_ERRORS as exc:
        return _go(back, err=f"Öneri oluşturulamadı: {exc}")
    return _go(back, msg=f"Öneri oluşturuldu: {KIND_LABELS[kind]}. Başka bir yöneticinin "
                         "onayı gerekiyor.")


# ───────────────────────── Seçmenler ─────────────────────────

@router.get("/voters")
def voters(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    rows = [gov.voter_plain(ctx, r) for r in ctx.conn.execute("SELECT * FROM voters ORDER BY id")]
    return _page(request, "admin/voters.html", admin, sess, voters=rows)


def parse_voter_lines(text: str) -> list[dict[str, Any]]:
    """Her satır: kimlik ; ad soyad ; e-posta (e-posta isteğe bağlı). Virgül de ayırıcıdır."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.replace(",", ";").split(";")]
        if len(parts) < 2:
            raise gov.GovernanceError(f"satır {n}: 'kimlik; ad soyad; e-posta' biçiminde olmalı")
        out.append({"id": parts[0], "display_name": parts[1],
                    "email": parts[2] if len(parts) > 2 and parts[2] else None})
    return out


@router.post("/voters")
async def voters_add(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    try:
        batch = parse_voter_lines(str(form.get("lines", "")))
    except gov.GovernanceError as exc:
        raise _go("/admin/voters", err=str(exc)) from None
    if not batch:
        raise _go("/admin/voters", err="En az bir seçmen girin.")
    raise _propose(ctx, admin, "voters_add", {"voters": batch}, "/admin/voters")


@router.post("/voters/{voter_id}/disable")
async def voter_disable(request: Request, voter_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    await _form(request, sess)
    raise _propose(ctx, admin, "voter_disable", {"id": voter_id}, "/admin/voters")


# ───────────────────────── Yöneticiler ─────────────────────────

@router.get("/admins")
def admins(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    rows = ctx.conn.execute("SELECT id, username, role, created_at, totp_secret_enc IS NOT NULL "
                            "AS has_totp, pw_hash LIKE 'enroll:%' AS pending FROM admins "
                            "ORDER BY created_at").fetchall()
    return _page(request, "admin/admins.html", admin, sess, admins=rows)


@router.post("/admins")
async def admin_add(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    username = str(form.get("username", "")).strip()
    part_a = enrollment.new_part()
    payload = {"id": username, "username": username, "role": str(form.get("role", "admin")),
               "enroll_a_hash": enrollment.hash_part(part_a)}
    try:
        gov.propose(ctx, admin["id"], "admin_add", payload)
    except DOMAIN_ERRORS as exc:
        raise _go("/admin/admins", err=f"Öneri oluşturulamadı: {exc}") from None
    # A parçası yalnızca önerene, bir kez gösterilir; sunucuda yalnızca özeti var.
    return _page(request, "admin/enroll_part.html", admin, sess, part_name="A",
                 username=username, part=part_a)


@router.get("/enroll")
def enroll_page(request: Request):
    return render(request, "admin/enroll.html", err=request.query_params.get("err"))


@router.post("/enroll")
def enroll(request: Request, username: str = Form(...), part_a: str = Form(...),
           part_b: str = Form(...), password: str = Form(...), password2: str = Form(...),
           ctx: Context = Depends(get_ctx)):
    if not request.app.state.limiter.allow(f"admin-enroll:{request.client.host}", 10, 600):
        raise _go("/admin/enroll", err="Çok fazla deneme. Biraz sonra tekrar deneyin.")
    if password != password2:
        raise _go("/admin/enroll", err="Parolalar eşleşmiyor.")
    try:
        enrollment.complete(ctx, username.strip(), part_a, part_b, password)
    except enrollment.EnrollmentError as exc:
        msg = ("Parola en az 12 karakter olmalı." if "at least" in str(exc) else
               "Etkinleştirme kodunun süresi dolmuş; yöneticiler yeniden önermeli."
               if "expired" in str(exc) else "Kullanıcı adı veya etkinleştirme kodları hatalı.")
        raise _go("/admin/enroll", err=msg) from None
    raise _go("/admin/login", err=None, msg="Hesabınız etkinleştirildi. Şimdi giriş yapıp "
                                            "iki adımlı doğrulamayı kurun.")


# ───────────────────────── Oylamalar ─────────────────────────

def parse_election_form(form: FormData, tz: str) -> tuple[str, dict[str, Any]]:
    bt = str(form.get("ballot_type", "single"))
    try:
        opens_at = to_utc_iso(str(form.get("opens_at", "")).strip(), tz)
        closes_at = to_utc_iso(str(form.get("closes_at", "")).strip(), tz)
    except ValueError:
        raise ConfigError("tarih/saat biçimi geçersiz") from None
    if not closes_at:
        raise ConfigError("Bitiş tarihi ve saati zorunludur.")
    options = [o.strip() for o in str(form.get("options", "")).splitlines() if o.strip()]
    ballot: dict[str, Any]
    if bt == "yes_no":
        ballot = {"allow_blank": form.get("allow_blank") == "on"}
    elif bt == "single":
        ballot = {"options": options, "allow_blank": form.get("allow_blank") == "on"}
    elif bt == "multi":
        try:
            lo = int(form.get("min_choices") or 0)
            hi = int(form.get("max_choices") or len(options))
        except ValueError:
            raise ConfigError("en az / en çok seçim sayıları tam sayı olmalı") from None
        ballot = {"options": options, "min_choices": lo, "max_choices": hi}
    elif bt == "approval":
        ballot = {"options": options}
    elif bt in ("borda", "ranked_irv"):
        ballot = {"options": options,
                  "require_full_ranking": form.get("require_full_ranking") == "on"}
    else:
        raise ConfigError(f"bilinmeyen oy türü: {bt}")
    try:
        min_turnout = int(form.get("min_turnout") or 3)
    except ValueError:
        raise ConfigError("asgari katılım tam sayı olmalı") from None
    cfg = {"ballot": ballot, "min_turnout": min_turnout,
           "opens_at": opens_at, "closes_at": closes_at,
           "auth_methods": [m for m in sorted(AUTH_METHODS) if form.get(f"auth_{m}") == "on"],
           "randomize_order": form.get("randomize_order") == "on"}
    return bt, cfg


@router.get("/elections/new")
def election_new_page(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    return _page(request, "admin/election_form.html", admin, sess, e=None,
                 cfg={"ballot": {}, "min_turnout": 3, "auth_methods": ["printed_code", "email_otp"],
                      "randomize_order": True, "opens_at": None, "closes_at": None},
                 bt="single", methods=sorted(AUTH_METHODS))


@router.post("/elections/new")
async def election_new(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    eid = str(form.get("id", "")).strip()
    try:
        gov._check_id(eid, "oylama kimliği")
        bt, cfg = parse_election_form(form, ctx.settings.timezone)
        gov.require_admin(ctx, admin["id"])
        service.create_election(ctx, admin["id"], eid, str(form.get("title", "")).strip() or eid,
                                bt, cfg)
    except DOMAIN_ERRORS as exc:
        raise _go("/admin/elections/new", err=str(exc)) from None
    except Exception as exc:  # ör. aynı kimlik
        if "UNIQUE" in str(exc):
            raise _go("/admin/elections/new", err="Bu kimlikte bir oylama zaten var.") from None
        raise
    raise _go(f"/admin/elections/{eid}", msg="Taslak oluşturuldu.")


@router.get("/elections/{election_id}")
def election_detail(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    e = service.get_election(ctx, election_id)
    cfg = json.loads(e["config"])
    roll = {r[0] for r in ctx.conn.execute(
        "SELECT voter_id FROM election_voters WHERE election_id = ?", (election_id,))}
    all_voters = [gov.voter_plain(ctx, r) for r in ctx.conn.execute(
        "SELECT id, display_name, email, status FROM voters ORDER BY id")]
    # Oy hakkı alan / sandıktaki oy sayıları burada BİLİNÇLİ OLARAK sorgulanmaz: katılım
    # bilgisi yalnızca bitiş zamanından sonra yapılan sayımın sonucunda (result) görünür.
    stats = {
        "roll": len(roll),
        "codes": ctx.conn.execute("SELECT COUNT(*) FROM auth_codes WHERE election_id = ? AND "
                                  "method = 'printed_code'", (election_id,)).fetchone()[0],
    }
    return _page(request, "admin/election.html", admin, sess, e=e, cfg=cfg, bt=e["ballot_type"],
                 window=service.window(e) if e["status"] == "open" else None,
                 roll=roll, all_voters=all_voters, stats=stats, methods=sorted(AUTH_METHODS),
                 result=json.loads(e["result"]) if e["result"] else None,
                 # Seçmen olay kaydı yalnızca sayımdan sonra gösterilir.
                 voter_log=ctx.conn.execute(
                     "SELECT seq, ts, voter_id, action FROM voter_log WHERE election_id = ? "
                     "ORDER BY seq", (election_id,)).fetchall() if e["result"] else [])


@router.post("/elections/{election_id}/config")
async def election_config(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    back = f"/admin/elections/{election_id}"
    try:
        gov.require_admin(ctx, admin["id"])
        bt, cfg = parse_election_form(form, ctx.settings.timezone)
        service.update_election(ctx, admin["id"], election_id,
                                title=str(form.get("title", "")).strip() or None,
                                ballot_type=bt, cfg=cfg)
    except DOMAIN_ERRORS as exc:
        raise _go(back, err=str(exc)) from None
    raise _go(back, msg="Yapılandırma kaydedildi.")


@router.post("/elections/{election_id}/roll")
async def election_roll(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    form = await _form(request, sess)
    back = f"/admin/elections/{election_id}"
    wanted = set(form.getlist("voter"))
    current = {r[0] for r in ctx.conn.execute(
        "SELECT voter_id FROM election_voters WHERE election_id = ?", (election_id,))}
    add, remove = sorted(wanted - current), sorted(current - wanted)
    if not add and not remove:
        raise _go(back, msg="Değişiklik yok.")
    try:
        if add:
            gov.propose(ctx, admin["id"], "roll_add", {"election_id": election_id,
                                                       "voter_ids": add})
        if remove:
            gov.propose(ctx, admin["id"], "roll_remove", {"election_id": election_id,
                                                          "voter_ids": remove})
    except DOMAIN_ERRORS as exc:
        raise _go(back, err=str(exc)) from None
    raise _go(back, msg=f"Liste değişikliği önerildi (+{len(add)} / -{len(remove)}). "
                        "Başka bir yöneticinin onayı gerekiyor.")


@router.post("/elections/{election_id}/open")
async def election_open(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    await _form(request, sess)
    raise _propose(ctx, admin, "election_open", {"election_id": election_id},
                   f"/admin/elections/{election_id}")


@router.post("/elections/{election_id}/close")
async def election_close(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    await _form(request, sess)
    raise _propose(ctx, admin, "election_close", {"election_id": election_id},
                   f"/admin/elections/{election_id}")


@router.post("/elections/{election_id}/codes")
async def election_codes(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    await _form(request, sess)
    try:
        codes = voter_auth.generate_printed_codes(ctx, admin["id"], election_id)
    except DOMAIN_ERRORS as exc:
        raise _go(f"/admin/elections/{election_id}", err=str(exc)) from None
    e = service.get_election(ctx, election_id)
    base = f"{request.url.scheme}://{request.url.netloc}/e/{election_id}"
    return _page(request, "admin/codes.html", admin, sess, e=e, codes=codes, url=base)


# ───────────────────────── Denetim ─────────────────────────

@router.get("/audit")
def audit(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    # Seçmen olayları bu zincirde değil (bkz. voter_log); burada sıra boşluğu oluşmaz.
    rows = []
    for r in ctx.conn.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 300"):
        d = dict(r)
        try:
            d["payload"] = json.dumps(chain.read_payload(ctx.keys, r), ensure_ascii=False)
        except Exception:
            d["payload"] = "⚠ çözülemedi (kurcalanmış olabilir)"
        rows.append(d)
    return _page(request, "admin/audit.html", admin, sess, rows=rows)


@router.get("/verify")
def verify(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    findings = verifier.verify(ctx.conn, ctx.keys, ctx.settings.checkpoint_path, ctx.settings)
    return _page(request, "admin/verify.html", admin, sess, findings=findings,
                 critical=sum(f.severity == "critical" for f in findings))


@router.post("/checkpoint")
async def take_checkpoint(request: Request, ctx: Context = Depends(get_ctx)):
    admin, sess = _admin(request, ctx)
    await _form(request, sess)
    checkpoint.take(ctx.conn, ctx.keys.checkpoint, ctx.settings.checkpoint_path)
    raise _go("/admin/verify", msg="Checkpoint alındı.")


__all__ = ["router", "ballot_types"]
