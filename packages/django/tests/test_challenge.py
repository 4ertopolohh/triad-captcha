from __future__ import annotations

import base64
import json
import os
import threading
import time

import pytest
import redis as redis_lib
from altcha import Challenge, Payload, create_challenge, solve_challenge, verify_solution
from django.contrib.sessions.models import Session
from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings

from triadcaptcha_django import redis_backend
from triadcaptcha_django.challenge import _derived_key_secret, verify_and_consume
from triadcaptcha_django.errors import ErrorCode, TriadCaptchaFailure
from triadcaptcha_django.models import BlockRule, SecurityEvent
from triadcaptcha_django.redis_backend import (
    clear_temporary_block,
    consume_challenge,
    create_attempt,
    get_int,
    increment,
    key,
    set_temporary_block,
)
from triadcaptcha_django.signals import (
    get_context_binding,
    hash_identity,
    hash_ip,
    hash_pair,
    set_context_cookie,
)
from triadcaptcha_django.site_keys import site_key_marker

from .helpers import issue_and_solve
from .urls import get_business_invocations, reset_business_invocations

pytestmark = pytest.mark.django_db


def test_challenge_is_hmac_signed_action_and_session_bound(client, settings, policy):
    response, payload, _ = issue_and_solve(client, settings)
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


def test_context_cookie_defaults_to_lax_and_http_compatible():
    request = RequestFactory().get("/")
    binding = get_context_binding(request, create=True)
    response = HttpResponse()
    set_context_cookie(response, binding.cookie_value, request)
    cookie = response.cookies["triadcaptcha_context"]
    assert cookie["samesite"] == "Lax"
    assert not cookie["secure"]


@override_settings(
    TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE="None",
    TRIADCAPTCHA_CONTEXT_COOKIE_SECURE=True,
)
def test_explicit_cross_site_context_cookie_is_none_and_secure():
    request = RequestFactory().get("/")
    binding = get_context_binding(request, create=True)
    response = HttpResponse()
    set_context_cookie(response, binding.cookie_value, request)
    cookie = response.cookies["triadcaptcha_context"]
    assert cookie["samesite"] == "None"
    assert cookie["secure"]


def test_missing_or_malformed_site_key_does_not_spend_issuance_quota(
    client, settings, policy
):
    policy.challenge_issue_limit = 1
    policy.save(update_fields=("challenge_issue_limit",))
    attempt = create_attempt(
        "register",
        site_key_marker(settings.TRIADCAPTCHA_SITE_KEY),
        "",
        "",
        90,
    )
    attempt_header = {"X-TriadCAPTCHA-Attempt": attempt}

    missing = client.get(
        "/api/triadcaptcha/challenge/", {"action": "register"}, headers=attempt_header
    )
    malformed = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": "register"},
        headers={**attempt_header, "X-TriadCAPTCHA-Site-Key": "bad key"},
    )
    malformed_attempt = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": "register"},
        headers={
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Attempt": "bad attempt",
        },
    )
    probe = RequestFactory().get("/", REMOTE_ADDR="127.0.0.1")
    ip_hash = hash_ip(probe)
    assert get_int(key("issue-precheck", "register", "ip", ip_hash)) == 0
    assert get_int(key("issue", "register", "ip", ip_hash)) == 0
    valid = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": "register"},
        headers={
            **attempt_header,
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        },
    )

    assert [
        missing.status_code,
        malformed.status_code,
        malformed_attempt.status_code,
        valid.status_code,
    ] == [400, 400, 400, 200]


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

    def headers_with_attempt():
        attempt = create_attempt(
            "register",
            site_key_marker(settings.TRIADCAPTCHA_SITE_KEY),
            "",
            "",
            90,
        )
        return {
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Attempt": attempt,
        }

    first = Client().get(
        "/api/triadcaptcha/challenge/",
        {"action": "register"},
        headers=headers_with_attempt(),
    )
    assert first.status_code == 200
    sessions_after_first = Session.objects.count()
    assert sessions_after_first == 1

    rejected = [
        Client().get(
            "/api/triadcaptcha/challenge/",
            {"action": "register"},
            headers=headers_with_attempt(),
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
    _, payload, attempt = issue_and_solve(client, settings)
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Payload": payload,
        "X-TriadCAPTCHA-Attempt": attempt,
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
    _, payload, attempt = issue_and_solve(client, settings)
    request = RequestFactory().post(
        "/login", HTTP_X_TRIADCAPTCHA_SITE_KEY=settings.TRIADCAPTCHA_SITE_KEY
    )
    request.COOKIES.update(client.cookies)
    # Copy the session established by the challenge endpoint.
    from django.contrib.sessions.middleware import SessionMiddleware

    SessionMiddleware(lambda req: None).process_request(request)
    request.session = client.session
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(request, ProtectedAction.objects.get(action="login"), payload, attempt)
    assert exc.value.public_error.code is ErrorCode.INVALID_PAYLOAD
    assert exc.value.internal_reason == "action_binding_mismatch"


def test_session_binding_rejects_other_browser(client, settings, policy):
    _, payload, attempt = issue_and_solve(client, settings)
    other_request = RequestFactory().post("/protected/")
    from django.contrib.sessions.middleware import SessionMiddleware

    SessionMiddleware(lambda req: None).process_request(other_request)
    other_request.session["_triadcaptcha_context"] = "another-session"
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(other_request, policy, payload, attempt)
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
        verify_and_consume(request, policy, payload, "A" * 43)
    assert exc.value.public_error.code is ErrorCode.CHALLENGE_EXPIRED
    assert exc.value.public_error.http_status == 410


def test_invalid_derived_key_and_prefix_are_rejected(client, settings, policy):
    _, payload, _ = issue_and_solve(client, settings)
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
    _, payload, attempt = issue_and_solve(client, settings)
    decoded = json.loads(base64.b64decode(payload))
    decoded["solution"]["derivedKey"] = "zz"
    malformed = base64.b64encode(json.dumps(decoded).encode()).decode()
    request = RequestFactory().post("/protected/")
    request.session = client.session
    with pytest.raises(TriadCaptchaFailure) as exc:
        verify_and_consume(request, policy, malformed, attempt)
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


def test_valid_retry_is_the_same_logical_attempt_near_rate_threshold(
    client, settings, policy
):
    policy.base_risk_score = 25
    policy.ip_identity_limit = 2
    policy.save(update_fields=("base_risk_score", "ip_identity_limit"))
    identity = {"type": "email", "value": "one@example.test"}
    probe = RequestFactory().post("/protected/", REMOTE_ADDR="127.0.0.1")
    pair = hash_pair(hash_ip(probe), hash_identity(identity))
    pair_key = key("rate", "register", "pair", pair)
    for _ in range(3):
        increment(pair_key, policy.rate_window_seconds)

    request_headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
    }
    initial = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers=request_headers,
    )
    assert initial.status_code == 428
    attempt = initial.json()["error"]["attempt"]
    count_after_initial = get_int(pair_key)

    challenge_response = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": "register"},
        headers={**request_headers, "X-TriadCAPTCHA-Attempt": attempt},
    )
    assert challenge_response.status_code == 200
    challenge = Challenge.from_dict(challenge_response.json()["challenge"])
    solution = solve_challenge(challenge, timeout=3)
    assert solution is not None
    proof = Payload(challenge, solution).to_base64()

    retried = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers={
            **request_headers,
            "X-TriadCAPTCHA-Attempt": attempt,
            "X-TriadCAPTCHA-Payload": proof,
        },
    )
    assert retried.status_code == 200
    assert get_int(pair_key) == count_after_initial


def test_retry_rechecks_authoritative_block_without_consuming_proof(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings)
    identity = {"type": "email", "value": "one@example.test"}
    rule = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash=hash_identity(identity),
        source=BlockRule.Source.MANUAL,
    )
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Attempt": attempt,
        "X-TriadCAPTCHA-Payload": proof,
    }
    blocked = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers=headers,
    )
    assert blocked.status_code == 403

    rule.active = False
    rule.save(update_fields=("active",))
    accepted = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers=headers,
    )
    assert accepted.status_code == 200


def test_retry_rechecks_temporary_block_without_consuming_proof(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings)
    identity = {"type": "email", "value": "one@example.test"}
    identity_hash = hash_identity(identity)
    set_temporary_block(
        BlockRule.Scope.IDENTITY,
        identity_hash,
        policy.action,
        60,
    )
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Attempt": attempt,
        "X-TriadCAPTCHA-Payload": proof,
    }

    blocked = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers=headers,
    )
    assert blocked.status_code == 403

    clear_temporary_block(BlockRule.Scope.IDENTITY, identity_hash, policy.action)
    accepted = client.post(
        "/protected/",
        data=json.dumps({"email": identity["value"]}),
        content_type="application/json",
        headers=headers,
    )
    assert accepted.status_code == 200


def test_same_session_different_identity_cannot_substitute_attempt(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings, identity="one@example.test")
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Attempt": attempt,
        "X-TriadCAPTCHA-Payload": proof,
    }
    substituted = client.post(
        "/protected/",
        data=json.dumps({"email": "two@example.test"}),
        content_type="application/json",
        headers=headers,
    )
    assert substituted.status_code == 400

    original = client.post(
        "/protected/",
        data=json.dumps({"email": "one@example.test"}),
        content_type="application/json",
        headers=headers,
    )
    assert original.status_code == 200


def test_logout_login_cannot_substitute_session_for_issued_proof(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings)
    client.logout()
    session = client.session
    session["authenticated_as"] = "one@example.test"
    session.save()

    response = client.post(
        "/protected/",
        data=json.dumps({"email": "one@example.test"}),
        content_type="application/json",
        headers={
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Action": "register",
            "X-TriadCAPTCHA-Attempt": attempt,
            "X-TriadCAPTCHA-Payload": proof,
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == ErrorCode.INVALID_PAYLOAD.value


def test_same_action_proof_is_an_action_audience_across_endpoints(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings)

    response = client.post(
        "/protected-alias/",
        data=json.dumps({"email": "one@example.test"}),
        content_type="application/json",
        headers={
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Action": "register",
            "X-TriadCAPTCHA-Attempt": attempt,
            "X-TriadCAPTCHA-Payload": proof,
        },
    )

    assert response.status_code == 200


@pytest.mark.skipif(
    os.environ.get("TRIADCAPTCHA_TEST_REAL_REDIS") != "1",
    reason="requires a real Redis service",
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_protected_endpoint_invokes_business_logic_once(
    client, settings, policy
):
    _, proof, attempt = issue_and_solve(client, settings)
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Attempt": attempt,
        "X-TriadCAPTCHA-Payload": proof,
    }
    cookies = client.cookies.copy()
    barrier = threading.Barrier(8)
    result_lock = threading.Lock()
    statuses = []
    failures = []
    reset_business_invocations()

    def submit():
        worker = Client()
        worker.cookies = cookies.copy()
        try:
            barrier.wait()
            response = worker.post(
                "/protected/",
                data=json.dumps({"email": "one@example.test"}),
                content_type="application/json",
                headers=headers,
            )
            with result_lock:
                statuses.append(response.status_code)
        except Exception as exc:  # pragma: no cover - reported below with context
            with result_lock:
                failures.append(exc)

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not failures
    assert statuses.count(200) == 1
    assert statuses.count(409) == 7
    assert get_business_invocations() == 1


@pytest.mark.skipif(
    os.environ.get("TRIADCAPTCHA_TEST_REAL_REDIS") != "1",
    reason="requires a real Redis service",
)
def test_real_redis_pool_exhaustion_returns_bounded_503(
    client, settings, policy, monkeypatch
):
    pool = redis_lib.BlockingConnectionPool.from_url(
        settings.TRIADCAPTCHA_REDIS_URL,
        max_connections=1,
        timeout=0.05,
        decode_responses=True,
    )
    bounded_client = redis_lib.Redis(connection_pool=pool)
    leased = pool.get_connection()
    monkeypatch.setattr(redis_backend, "get_redis_client", lambda: bounded_client)
    reset_business_invocations()

    started = time.monotonic()
    try:
        response = client.post(
            "/protected/",
            data=json.dumps({"email": "one@example.test"}),
            content_type="application/json",
            headers={
                "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
                "X-TriadCAPTCHA-Action": "register",
            },
        )
    finally:
        pool.release(leased)
        pool.disconnect()

    assert time.monotonic() - started < 1
    assert response.status_code == 503
    assert get_business_invocations() == 0


def test_invalid_proof_attempts_are_bounded_without_recounting_business_attempt(
    client, settings, policy
):
    policy.proof_retry_limit = 3
    policy.save(update_fields=("proof_retry_limit",))
    _, _, attempt = issue_and_solve(client, settings)
    identity = {"type": "email", "value": "one@example.test"}
    probe = RequestFactory().post("/protected/", REMOTE_ADDR="127.0.0.1")
    pair_key = key(
        "rate",
        "register",
        "pair",
        hash_pair(hash_ip(probe), hash_identity(identity)),
    )
    count_after_initial = get_int(pair_key)
    headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": "register",
        "X-TriadCAPTCHA-Attempt": attempt,
        "X-TriadCAPTCHA-Payload": "bm90LWEtcHJvb2Y=",
    }

    statuses = [
        client.post(
            "/protected/",
            data=json.dumps({"email": identity["value"]}),
            content_type="application/json",
            headers=headers,
        ).status_code
        for _ in range(3)
    ]

    assert statuses == [400, 400, 429]
    assert get_int(pair_key) == count_after_initial
