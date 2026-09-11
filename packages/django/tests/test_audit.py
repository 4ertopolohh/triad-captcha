from __future__ import annotations

import json

import pytest

from triadcaptcha_django.audit import AuditSignals, write_event
from triadcaptcha_django.models import SecurityEvent

pytestmark = pytest.mark.django_db


def _signals(*, identity: str, session: str) -> AuditSignals:
    return AuditSignals(
        ip_hash="a" * 64,
        identity_hash=identity,
        session_hash=session,
        ip_identity_hash="d" * 64,
        user_agent_family="chromium",
    )


def test_forced_event_dedupe_preserves_distinct_contexts_behind_one_ip():
    first = _signals(identity="b" * 64, session="c" * 64)
    second = _signals(identity="e" * 64, session="f" * 64)

    for signals in (first, first, second, second):
        write_event(
            action="register",
            decision=SecurityEvent.Decision.BLOCK,
            public_code="ANTIBOT_BLOCKED",
            reasons=("rate_identity", "rate_ip"),
            signals=signals,
            force=True,
        )

    events = list(SecurityEvent.objects.order_by("pk"))
    assert len(events) == 2
    assert {event.identity_hash for event in events} == {"b" * 64, "e" * 64}
    assert {event.session_hash for event in events} == {"c" * 64, "f" * 64}


def test_audit_storage_contains_only_pseudonymous_identifiers():
    raw_identity = "person@example.test"
    raw_ip = "192.0.2.10"
    write_event(
        action="register",
        decision=SecurityEvent.Decision.BLOCK,
        signals=_signals(identity="b" * 64, session="c" * 64),
        metadata={"focus_count": 2},
        force=True,
    )

    serialized = json.dumps(
        SecurityEvent.objects.values().get(),
        default=str,
        sort_keys=True,
    )
    assert raw_identity not in serialized
    assert raw_ip not in serialized
