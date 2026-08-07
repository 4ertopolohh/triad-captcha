from __future__ import annotations

import base64
import json

import pytest
from django.test import RequestFactory, override_settings
from redis.exceptions import ConnectionError

from triadcaptcha_django import redis_backend
from triadcaptcha_django import service as service_module
from triadcaptcha_django.errors import ErrorCode
from triadcaptcha_django.models import BlockRule, ProtectionConfiguration, SecurityEvent
from triadcaptcha_django.service import evaluate, record_outcome
from triadcaptcha_django.signals import hash_identity, hash_ip
from triadcaptcha_django.types import Decision

pytestmark = pytest.mark.django_db


def _request(*, identity="person@example.test", metadata=None):
    headers = {
        "HTTP_X_TRIADCAPTCHA_SITE_KEY": "tc_site_test_public_identifier_123456789",
        "HTTP_X_TRIADCAPTCHA_ACTION": "register",
    }
    if metadata is not None:
        encoded = base64.urlsafe_b64encode(json.dumps(metadata).encode()).decode().rstrip("=")
        headers["HTTP_X_TRIADCAPTCHA_METADATA"] = encoded
    request = RequestFactory().post("/protected/", **headers)
    request.META["REMOTE_ADDR"] = "192.0.2.10"
    request.identity = identity
    return request


def test_low_risk_request_is_allowed(policy):
    result = evaluate(_request(), "register", identity="person@example.test")
    assert result.decision is Decision.ALLOW
    assert result.code is None


def test_protected_request_requires_public_site_key(policy):
    request = _request()
    request.META.pop("HTTP_X_TRIADCAPTCHA_SITE_KEY")
    result = evaluate(request, "register", identity="person@example.test")
    assert result.code == ErrorCode.INVALID_PAYLOAD.value
    assert result.http_status == 400


def test_ip_limit_crossing_requires_challenge_but_never_ip_only_block(policy):
    policy.ip_limit = 1
    policy.challenge_threshold = 40
    policy.block_threshold = 50
    policy.save()
    first = evaluate(_request(), "register", identity=None)
    second = evaluate(_request(), "register", identity=None)
    third = evaluate(_request(), "register", identity=None)
    assert first.allowed
    assert second.decision is Decision.CHALLENGE_REQUIRED
    assert third.decision is Decision.CHALLENGE_REQUIRED


def test_identity_plus_pair_rate_can_create_temporary_block(policy):
    policy.identity_limit = 1
    policy.ip_identity_limit = 1
    policy.block_threshold = 60
    policy.save()
    request = _request()
    evaluate(request, "register", identity="person@example.test")
    result = evaluate(_request(), "register", identity="person@example.test")
    assert result.decision is Decision.BLOCK
    assert result.code == ErrorCode.BLOCKED.value
    assert BlockRule.objects.filter(source=BlockRule.Source.AUTOMATIC, active=True).exists()


def test_diversity_set_is_capped_after_threshold(policy, redis_client):
    policy.identities_per_ip_limit = 2
    policy.ip_limit = 100
    policy.save(update_fields=("identities_per_ip_limit", "ip_limit"))

    for index in range(20):
        evaluate(
            _request(),
            "register",
            identity={"type": "email", "value": f"person-{index}@example.test"},
        )

    ip_hash = hash_ip(_request())
    diversity_key = redis_backend.key("diversity", "register", "ip", ip_hash)
    assert redis_client.scard(diversity_key) == policy.identities_per_ip_limit + 1


def test_weak_metadata_alone_does_not_block(policy):
    policy.challenge_threshold = 20
    policy.block_threshold = 25
    policy.save()
    result = evaluate(
        _request(metadata={"honeypot_filled": True, "form_fill_ms": 10}),
        "register",
        identity=None,
    )
    assert result.decision is Decision.CHALLENGE_REQUIRED
    assert result.code == ErrorCode.CHALLENGE_REQUIRED.value


def test_repeated_business_failures_raise_risk(policy):
    policy.failure_limit = 2
    policy.save()
    request = _request()
    record_outcome(request, "register", "person@example.test", outcome="password_failure")
    record_outcome(request, "register", "person@example.test", outcome="password_failure")
    result = evaluate(_request(), "register", identity="person@example.test")
    assert result.decision is Decision.CHALLENGE_REQUIRED


def test_success_outcomes_honor_audit_sampling(policy):
    ProtectionConfiguration.objects.filter(pk=1).update(allow_audit_sample_rate=0)
    record_outcome(_request(), "register", "person@example.test", outcome="success")
    assert not SecurityEvent.objects.filter(decision=SecurityEvent.Decision.OUTCOME).exists()


def test_outcome_redis_failure_does_not_turn_committed_success_into_error(
    policy, monkeypatch
):
    ProtectionConfiguration.objects.filter(pk=1).update(allow_audit_sample_rate=0)

    class BrokenRedis:
        def delete(self, *args, **kwargs):
            raise ConnectionError("offline")

    monkeypatch.setattr(redis_backend, "get_redis_client", lambda: BrokenRedis())
    record_outcome(_request(), "register", "person@example.test", outcome="success")

    event = SecurityEvent.objects.get(decision=SecurityEvent.Decision.OUTCOME)
    assert event.reason_codes == ["business_success", "outcome_redis_unavailable"]


def test_redis_outage_fails_closed(policy, monkeypatch):
    class BrokenRedis:
        def eval(self, *args, **kwargs):
            raise ConnectionError("offline")

        def ttl(self, *args, **kwargs):
            raise ConnectionError("offline")

    monkeypatch.setattr(redis_backend, "get_redis_client", lambda: BrokenRedis())
    result = evaluate(_request(), "register", identity="person@example.test")
    assert result.code == ErrorCode.SERVICE_UNAVAILABLE.value
    assert result.http_status == 503


def test_supplied_proof_never_fails_open(policy, monkeypatch):
    policy.fail_closed = False
    policy.save()

    class BrokenRedis:
        def eval(self, *args, **kwargs):
            raise ConnectionError("offline")

        def ttl(self, *args, **kwargs):
            raise ConnectionError("offline")

    monkeypatch.setattr(redis_backend, "get_redis_client", lambda: BrokenRedis())
    result = evaluate(_request(), "register", payload="bogus-proof")
    assert result.code == ErrorCode.SERVICE_UNAVAILABLE.value


def test_consume_outage_after_risk_evaluation_is_classified(policy, monkeypatch):
    def unavailable(*args, **kwargs):
        raise redis_backend.RedisUnavailable("offline during consume")

    monkeypatch.setattr(service_module, "verify_and_consume", unavailable)
    result = evaluate(_request(), "register", payload="syntactically-deferred")
    assert result.code == ErrorCode.SERVICE_UNAVAILABLE.value
    assert "challenge_consume_unavailable" in result.reasons


def test_lone_surrogate_payload_maps_to_public_invalid_payload(client, settings, policy):
    response = client.post(
        "/protected/",
        data='{"_triadcaptcha":"\\ud800"}',
        content_type="application/json",
        headers={
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Action": "register",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == ErrorCode.INVALID_PAYLOAD.value


def test_untrusted_forwarded_for_is_ignored(policy, settings):
    request = _request()
    request.META["REMOTE_ADDR"] = "203.0.113.10"
    request.META["HTTP_X_FORWARDED_FOR"] = "198.51.100.20"
    direct_hash = hash_ip(request)
    request.META["HTTP_X_FORWARDED_FOR"] = "192.0.2.99"
    assert hash_ip(request) == direct_hash


@override_settings(TRIADCAPTCHA_TRUSTED_PROXY_NETWORKS=["203.0.113.0/24"])
def test_forwarded_for_is_used_only_behind_trusted_proxy(policy):
    first = _request()
    first.META["REMOTE_ADDR"] = "203.0.113.10"
    first.META["HTTP_X_FORWARDED_FOR"] = "198.51.100.20"
    second = _request()
    second.META["REMOTE_ADDR"] = "203.0.113.10"
    second.META["HTTP_X_FORWARDED_FOR"] = "198.51.100.21"
    assert hash_ip(first) != hash_ip(second)


def test_metadata_contract_accepts_react_field_names(policy):
    metadata = {
        "form_fill_ms": 5000,
        "focus_count": 1,
        "input_count": 4,
        "pointer_count": 2,
        "keyboard_count": 4,
        "page_visible": True,
        "honeypot_filled": False,
    }
    result = evaluate(_request(metadata=metadata), "register", identity="person@example.test")
    assert result.allowed


def test_identity_is_hmac_hashed_and_normalized(settings):
    first = hash_identity({"type": "email", "value": " Person@Example.TEST "})
    second = hash_identity({"type": "email", "value": "person@example.test"})
    assert first == second
    assert "person" not in first
    assert len(first) == 64
