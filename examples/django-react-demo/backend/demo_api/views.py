"""Minimal regular-Django integration; no DRF is involved."""

from __future__ import annotations

import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST
from triadcaptcha_django import record_outcome
from triadcaptcha_django.decorators import protect


def _json(request: HttpRequest) -> dict[str, object]:
    try:
        value = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _email_identity(request: HttpRequest) -> dict[str, str]:
    # Only the value selected for risk correlation is passed to TriadCAPTCHA. The
    # package normalizes and HMAC-hashes it before Redis/audit storage.
    value = _json(request).get("email", "")
    return {"type": "email", "value": str(value)}


@require_GET
def health(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


@ensure_csrf_cookie
@require_GET
def csrf(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


@require_POST
@protect("register", identity_getter=_email_identity)
def register(request: HttpRequest) -> JsonResponse:
    data = _json(request)
    record_outcome(request, "register", _email_identity(request), outcome="success")
    return JsonResponse({"ok": True, "demo": "register", "email": bool(data.get("email"))})


@require_POST
@protect("login", identity_getter=_email_identity)
def login(request: HttpRequest) -> JsonResponse:
    data = _json(request)
    if data.get("password") != "demo-password":
        record_outcome(
            request,
            "login",
            _email_identity(request),
            outcome="password_failure",
        )
        return JsonResponse({"ok": False, "code": "INVALID_CREDENTIALS"}, status=401)
    record_outcome(request, "login", _email_identity(request), outcome="success")
    return JsonResponse({"ok": True, "demo": "login", "email": bool(data.get("email"))})


@require_POST
@protect("lead", identity_getter=_email_identity)
def lead(request: HttpRequest) -> JsonResponse:
    data = _json(request)
    record_outcome(request, "lead", _email_identity(request), outcome="success")
    return JsonResponse({"ok": True, "demo": "lead", "contact": bool(data.get("email"))})
