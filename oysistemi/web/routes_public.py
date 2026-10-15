"""Seçmen ve kamuya açık rotalar.

İki bölge birbirinden kesin ayrılır:
  • Kimlik bölgesi (/e/{id}/login, /api/e/{id}/issue): oturum çerezi var, seçmen bellidir.
  • Sandık bölgesi (/api/e/{id}/cast): çerez KULLANILMAZ, IP tutulmaz, loglanmaz.
"""
from __future__ import annotations

import base64
import binascii
import json
import random
from typing import Any

from fastapi import APIRouter, Depends, Form, Header, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from ..auth import voter_auth
from ..context import Context
from ..crypto import keystore
from ..elections import ballot_types, service
from ..voting import ballot_box, issuer
from .app import Redirect, get_ctx, localtime, render
from .security import VOTER_COOKIE, VOTER_TTL, new_csrf, set_cookie, sign, unsign

router = APIRouter()
_sysrand = random.SystemRandom()


def _client(request: Request) -> str:
    return request.client.host if request.client else "?"


def _limit(request: Request, bucket: str, limit: int, window: float) -> bool:
    return request.app.state.limiter.allow(f"{bucket}:{_client(request)}", limit, window)


def _voter_session(request: Request, election_id: str) -> dict[str, Any] | None:
    s = unsign(request.app.state.keys.session, "voter", request.cookies.get(VOTER_COOKIE))
    return s if s and s.get("eid") == election_id else None


@router.get("/")
def index(request: Request, ctx: Context = Depends(get_ctx)):
    rows = [{"id": r["id"], "title": r["title"], "status": r["status"],
             "closes_at": json.loads(r["config"])["closes_at"]}
            for r in ctx.conn.execute("SELECT id, title, status, config FROM elections WHERE "
                                      "status IN ('open', 'tallied') ORDER BY status, title")]
    return render(request, "index.html", elections=rows)


@router.get("/e/{election_id}")
def login_page(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    e = service.get_election(ctx, election_id)
    if e["status"] == "tallied":
        raise Redirect(f"/e/{election_id}/results")
    if e["status"] != "open":
        return render(request, "error.html", 404, title="Oylama açık değil",
                      message="Bu oylama şu anda oy kullanıma açık değil.")
    cfg = json.loads(e["config"])
    w = service.window(e)
    if w != "during":
        return render(request, "error.html", 200, title=e["title"], message=(
            f"Oy verme {localtime(cfg['opens_at'], request.app.state.settings.timezone)} "
            f"tarihinde başlayacak." if w == "before" else
            "Oy verme süresi sona erdi. Sonuçlar sayım tamamlanınca yayımlanacak."))
    return render(request, "login.html", e=e, cfg=cfg, methods=cfg["auth_methods"],
                  error=request.query_params.get("err"))


@router.post("/e/{election_id}/login")
def login(request: Request, election_id: str, voter_id: str = Form(...), code: str = Form(...),
          method: str = Form(...), ctx: Context = Depends(get_ctx)):
    if not _limit(request, "voter-login", 20, 600):
        raise Redirect(f"/e/{election_id}?err=rate")
    try:
        ok = voter_auth.verify_code(ctx, election_id, voter_id.strip(), method, code)
    except voter_auth.VoterAuthError:
        ok = False
    if not ok:
        raise Redirect(f"/e/{election_id}?err=code")
    resp = Response(status_code=303, headers={"Location": f"/e/{election_id}/vote"})
    set_cookie(resp, VOTER_COOKIE,
               sign(request.app.state.keys.session, "voter",
                    {"vid": voter_id.strip(), "eid": election_id, "csrf": new_csrf()}, VOTER_TTL),
               VOTER_TTL, request.app.state.settings.cookie_secure)
    return resp


@router.post("/e/{election_id}/email")
def email_code(request: Request, election_id: str, voter_id: str = Form(...),
               ctx: Context = Depends(get_ctx)):
    e = service.get_election(ctx, election_id)
    if _limit(request, "voter-email", 5, 600):
        try:
            voter_auth.request_email_otp(ctx, election_id, voter_id.strip())
        except voter_auth.VoterAuthError:
            pass
    # Seçmen var olsun olmasın aynı yanıt: liste dışarıdan yoklanamaz.
    return render(request, "login.html", e=e, methods=json.loads(e["config"])["auth_methods"],
                  email_sent=True, voter_id=voter_id.strip())


@router.get("/e/{election_id}/vote")
def vote_page(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    sess = _voter_session(request, election_id)
    if sess is None:
        raise Redirect(f"/e/{election_id}")
    e = service.get_election(ctx, election_id)
    if e["status"] != "open":
        raise Redirect(f"/e/{election_id}")
    cfg = json.loads(e["config"])
    options = ballot_types.get(e["ballot_type"]).options(cfg["ballot"])
    if cfg.get("randomize_order"):
        _sysrand.shuffle(options)
    return render(request, "vote.html", e=e, cfg=cfg, options=options, csrf=sess["csrf"])


@router.post("/voter/logout")
def voter_logout():
    resp = Response(status_code=204)
    resp.delete_cookie(VOTER_COOKIE, path="/")
    return resp


@router.get("/api/e/{election_id}/key")
def public_key(election_id: str, ctx: Context = Depends(get_ctx)):
    e = service.get_election(ctx, election_id)
    if e["pubkey_pem"] is None:
        return JSONResponse({"error": "not_open"}, status_code=404)
    return keystore.public_json(e["pubkey_pem"])


class IssueBody(BaseModel):
    blinded: str


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("bad base64") from None


@router.post("/api/e/{election_id}/issue")
def issue(request: Request, election_id: str, body: IssueBody,
          x_csrf_token: str = Header(default=""), ctx: Context = Depends(get_ctx)):
    sess = _voter_session(request, election_id)
    if sess is None or x_csrf_token != sess["csrf"]:
        return JSONResponse({"error": "not_authenticated"}, status_code=401)
    try:
        blind_sig = issuer.issue(ctx, election_id, sess["vid"], _b64(body.blinded))
    except issuer.AlreadyIssued:
        return JSONResponse({"error": "already_issued"}, status_code=409)
    except (issuer.IssuanceError, ValueError) as exc:
        return JSONResponse({"error": "refused", "detail": str(exc)}, status_code=403)
    return {"blind_sig": base64.b64encode(blind_sig).decode()}


class CastBody(BaseModel):
    token: str
    sig: str
    ballot: Any


@router.post("/api/e/{election_id}/cast")
def cast(request: Request, election_id: str, body: CastBody, ctx: Context = Depends(get_ctx)):
    # Bilinçli olarak: çerez okunmaz, IP'ye göre sınırlama/log yapılmaz.
    if not request.app.state.limiter.allow("cast-global", 120, 60):
        return JSONResponse({"error": "busy"}, status_code=429)
    try:
        receipt = ballot_box.cast(ctx, election_id, _b64(body.token), _b64(body.sig), body.ballot)
    except ballot_box.AlreadyVoted:
        return JSONResponse({"error": "already_voted"}, status_code=409)
    except (ballot_box.CastError, ValueError) as exc:
        return JSONResponse({"error": "refused", "detail": str(exc)}, status_code=400)
    return {"receipt": receipt}


@router.get("/e/{election_id}/results")
def results(request: Request, election_id: str, ctx: Context = Depends(get_ctx)):
    e = service.get_election(ctx, election_id)
    if e["status"] not in ("tallied", "archived"):
        return render(request, "error.html", 404, title="Sonuçlar henüz yok",
                      message="Sonuçlar oylama kapandıktan sonra yayımlanır.")
    board = service.bulletin(ctx, election_id)
    return render(request, "results.html", e=e, board=board, result=board["result"])


@router.get("/api/e/{election_id}/bulletin.json")
def bulletin(election_id: str, ctx: Context = Depends(get_ctx)):
    try:
        return service.bulletin(ctx, election_id)
    except service.ElectionStateError:
        return JSONResponse({"error": "not_published"}, status_code=404)
