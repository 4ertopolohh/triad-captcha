from __future__ import annotations

import os

import fakeredis
import pytest
import redis

from triadcaptcha_django import redis_backend
from triadcaptcha_django.conf import get_settings
from triadcaptcha_django.models import (
    ProtectedAction,
    ProtectionConfiguration,
    SiteKeyVersion,
)


@pytest.fixture(autouse=True)
def redis_client(monkeypatch):
    use_real_redis = os.environ.get("TRIADCAPTCHA_TEST_REAL_REDIS") == "1"
    if use_real_redis:
        client = redis.Redis.from_url(
            get_settings().redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
    else:
        client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_backend, "get_redis_client", lambda: client)
    pattern = f"{get_settings().redis_prefix.strip(':')}:v1:*"
    keys = list(client.scan_iter(match=pattern, count=500))
    if keys:
        client.delete(*keys)
    yield client
    keys = list(client.scan_iter(match=pattern, count=500))
    if keys:
        client.delete(*keys)


@pytest.fixture
def policy(db, settings):
    ProtectionConfiguration.objects.create(pk=1, allow_audit_sample_rate=1.0)
    SiteKeyVersion.objects.create(site_key=settings.TRIADCAPTCHA_SITE_KEY)
    return ProtectedAction.objects.create(
        action="register",
        pow_cost=1,
        pow_min_counter=1,
        pow_max_counter=3,
        challenge_ttl_seconds=30,
    )
