from __future__ import annotations

import json

from altcha import Challenge, Payload, solve_challenge
from django.conf import settings
from django.test import TestCase
from triadcaptcha_django.models import (
    ProtectedAction,
    ProtectionConfiguration,
    SiteKeyVersion,
)
from triadcaptcha_django.redis_backend import get_redis_client, key


class ProtectedDemoFlowTests(TestCase):
    """Exercise the ordinary Django view and real configured Redis together."""

    @classmethod
    def _clear_owned_redis_keys(cls) -> None:
        client = get_redis_client()
        keys = list(client.scan_iter(match=key("*"), count=500))
        if keys:
            client.delete(*keys)

    def setUp(self) -> None:
        self._clear_owned_redis_keys()
        ProtectionConfiguration.objects.create(pk=1, allow_audit_sample_rate=1.0)
        SiteKeyVersion.objects.create(site_key=settings.TRIADCAPTCHA_SITE_KEY)
        self.policy = ProtectedAction.objects.create(
            action="register",
            base_risk_score=40,
            challenge_threshold=40,
            block_threshold=80,
            pow_cost=1,
            pow_min_counter=1,
            pow_max_counter=3,
            challenge_ttl_seconds=30,
        )

    def tearDown(self) -> None:
        self._clear_owned_redis_keys()

    def test_challenge_solve_retry_and_replay_on_demo_view(self) -> None:
        request_headers = {
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Action": "register",
        }
        body = json.dumps({"email": "demo@example.test", "password": "unused"})
        initial = self.client.post(
            "/api/register/",
            data=body,
            content_type="application/json",
            headers=request_headers,
        )
        self.assertEqual(initial.status_code, 428)
        self.assertEqual(
            initial.json()["error"]["code"], "ANTIBOT_CHALLENGE_REQUIRED"
        )

        challenge_response = self.client.get(
            "/api/triadcaptcha/challenge/",
            {"action": "register"},
            headers={"X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY},
        )
        self.assertEqual(challenge_response.status_code, 200)
        challenge = Challenge.from_dict(challenge_response.json()["challenge"])
        solution = solve_challenge(challenge, timeout=3)
        self.assertIsNotNone(solution)
        proof = Payload(challenge, solution).to_base64()

        protected_headers = {**request_headers, "X-TriadCAPTCHA-Payload": proof}
        accepted = self.client.post(
            "/api/register/",
            data=body,
            content_type="application/json",
            headers=protected_headers,
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertTrue(accepted.json()["ok"])

        replay = self.client.post(
            "/api/register/",
            data=body,
            content_type="application/json",
            headers=protected_headers,
        )
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(replay.json()["error"]["code"], "ANTIBOT_CHALLENGE_REPLAYED")
