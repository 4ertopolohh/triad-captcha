from __future__ import annotations

import base64
import json
import threading
import time

import pytest
from altcha import Payload, create_challenge, solve_challenge, verify_solution
from django.contrib.sessions.models import Session
from django.test import Client, RequestFactory

from triadcaptcha_django.challenge import _derived_key_secret, verify_and_consume
from triadcaptcha_django.errors import ErrorCode, TriadCaptchaFailure
from triadcaptcha_django.models import SecurityEvent
from triadcaptcha_django.redis_backend import consume_challenge, key
from triadcaptcha_django.signals import get_context_binding

from .helpers import issue_and_solve

pytestmark = pytest.mark.django_db


def test_challenge_is_hmac_signed_action_and_session_bound(client, settings, policy):
    response, payload = issue_and_solve(client, settings)
    data = response.json()["challenge"]
    verified = verify_solution(
        payload,
        settings.TRIADCAPTCHA_HMAC_SECRET,
        hmac_key_secret=_derived_key_secret(),
    )
    assert verified.verified
    signed = data["parameters"]["data"]
    assert signed["action"] == "register"
    assert "context" not in signed
    assert signed["jti"]
    assert settings.TRIADCAPTCHA_HMAC_SECRET not in response.content.decode()


def test_challenge_endpoint_requires_public_site_key_header(client, policy):
    response = client.get("/api/triadcaptcha/challenge/", {"action": "register"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == ErrorCode.INVALID_PAYLOAD.value


def test_invalid_challenge_request_is_classified_in_admin_audit(client, policy):
    response = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": "INVALID ACTION"},
        headers={"X-TriadCAPTCHA-Site-Key": "tc_site_test_public_identifier_123456789"},
    )
    assert response.status_code == 400
    event = SecurityEvent.objects.get(public_code=ErrorCode.INVALID_PAYLOAD.value)
    assert event.action == "invalid"
    assert event.reason_codes == ["invalid_action"]


def test_ip_issue_limit_precedes_new_session_allocation(settings, policy):
    policy.challenge_issue_limit = 1
    policy.save(update_fields=("challenge_issue_limit",))
    headers = {"X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY}

    first = Client().get(
        "/api/triadcaptcha/challenge/", {"action": "register"}, headers=headers
    )
    assert first.status_code == 200
    sessions_after_first = Session.objects.count()
    assert sessions_after_first == 1

    rejected = [
        Client().get(
            "/api/triadcaptcha/challenge/", {"action": "register"}, headers=headers
        )
        for _ in range(8)
    ]
    assert all(response.status_code == 429 for response in rejected)
    assert all(
        response.json()["error"]["code"] == ErrorCode.RATE_LIMITED.value
        for response in rejected
    )
    assert all(settings.SESSION_COOKIE_NAME not in response.cookies for response in rejected)
    assert Session.objects.count() == sessions_after_first
    assert (
        SecurityEvent.objects.filter(public_code=ErrorCode.RATE_LIMITED.value).count()
        == 1
    )


def test_valid_payload_is_consumed_once(client, settings, policy):
    policy.base_risk_score = policy.challenge_threshold
    policy.save(update_fields=("base_risk_score",))
    _, payload = issue_and_solve(client, settings)
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Payload": payload,
    }
    first = client.post(
        "/protected/",
        data=json.dumps({"email": "one@example.test"}),
        content_type="application/json",
        headers=headers,
    )
    second = client.post(
        "/protected/",
        data=json.dumps({"email": "one@example.test"}),
        content_type="application/json",
        headers=headers,
    )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == ErrorCode.CHALLENGE_REPLAYED.value


def test_action_binding_rejects_valid_solution_for_another_action(client, settings, policy):
    from triadcaptcha_django.models import ProtectedAction

    ProtectedAction.objects.create(action="login", pow_cost=1, pow_min_counter=1, pow_max_counter=3)
    _, payload = issue_and_solve(client, settings)
    request = RequestFactory().post(
        "/login", HTTP_X_TRIADCAPTCHA_SITE_KEY=settings.TRIADCAPTCHA_SITE_KEY
    )
    request.COOKIES.update(client.cookies)
    # Copy the session established by the challenge endpoint.
    from django.contrib.sessions.middleware import SessionMiddleware

    SessionMiddleware(lambda req: None).process_request(request)
    request.session = client.session
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(request, ProtectedAction.objects.get(action="login"), payload)
    assert exc.value.public_error.code is ErrorCode.INVALID_PAYLOAD
    assert exc.value.internal_reason == "action_binding_mismatch"


def test_session_binding_rejects_other_browser(client, settings, policy):
    _, payload = issue_and_solve(client, settings)
    other_request = RequestFactory().post("/protected/")
    from django.contrib.sessions.middleware import SessionMiddleware

    SessionMiddleware(lambda req: None).process_request(other_request)
    other_request.session["_triadcaptcha_context"] = "another-session"
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(other_request, policy, payload)
    assert exc.value.internal_reason == "session_binding_mismatch"


def test_expired_altcha_payload_maps_to_410(client, settings, policy):
    context = get_context_binding(client.request().wsgi_request, create=True)
    challenge = create_challenge(
        "PBKDF2/SHA-256",
        1,
        counter=1,
        expires_at=int(time.time()) - 1,
        data={
            "jti": "A" * 24,
            "action": "register",
            "context": context.context_hash,
            "siteKey": "unused",
        },
        hmac_secret=settings.TRIADCAPTCHA_HMAC_SECRET,
        hmac_key_secret=_derived_key_secret(),
    )
    solution = solve_challenge(challenge, timeout=2)
    payload = Payload(challenge, solution).to_base64()
    request = RequestFactory().post("/protected/")
    request.session = client.session
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(request, policy, payload)
    assert exc.value.public_error.code is ErrorCode.CHALLENGE_EXPIRED
    assert exc.value.public_error.http_status == 410


def test_invalid_derived_key_and_prefix_are_rejected(client, settings, policy):
    _, payload = issue_and_solve(client, settings)
    decoded = json.loads(base64.b64decode(payload))
    decoded["solution"]["derivedKey"] = "00" * 32
    tampered = base64.b64encode(json.dumps(decoded).encode()).decode()
    result = verify_solution(
        tampered,
        settings.TRIADCAPTCHA_HMAC_SECRET,
        hmac_key_secret=_derived_key_secret(),
    )
    assert not result.verified
    assert result.invalid_solution


def test_non_hex_derived_key_maps_to_invalid_payload_not_service_failure(client, settings, policy):
    _, payload = issue_and_solve(client, settings)
    decoded = json.loads(base64.b64decode(payload))
    decoded["solution"]["derivedKey"] = "zz"
    malformed = base64.b64encode(json.dumps(decoded).encode()).decode()
    request = RequestFactory().post("/protected/")
    request.session = client.session
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(request, policy, malformed)
    assert exc.value.public_error.code is ErrorCode.INVALID_PAYLOAD
    assert exc.value.internal_reason == "altcha_invalid_structure"


def test_atomic_consume_has_exactly_one_winner(redis_client):
    jti = "atomic-jti-012345678901234"
    marker = "register|context|site"
    redis_client.set(key("challenge", jti), marker, ex=30)
    barrier = threading.Barrier(8)
    results = []

    def consume():
        barrier.wait()
        results.append(consume_challenge(jti, marker, 60))

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(1) == 1
    assert results.count(2) == 7
