from __future__ import annotations

import json
import multiprocessing
import os
import secrets

import pytest

from triadcaptcha_django import audit as audit_module
from triadcaptcha_django.audit import AuditSignals, write_event
from triadcaptcha_django.models import SecurityEvent

pytestmark = pytest.mark.django_db


def _redis_dedupe_worker(token, ready, start, results) -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    import django

    django.setup()
    from triadcaptcha_django.audit import _first_forced_event_in_window

    ready.put(True)
    if not start.wait(timeout=10):
        results.put(RuntimeError("dedupe worker start barrier timed out"))
        return
    results.put(_first_forced_event_in_window(token))


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


def test_redis_outage_uses_bounded_process_local_dedupe(monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("Redis unavailable")

    monkeypatch.setattr(audit_module, "increment", unavailable)
    monkeypatch.setattr(audit_module, "_LOCAL_DEDUPE_LIMIT", 2)
    with audit_module._local_dedupe_lock:
        audit_module._local_dedupe.clear()

    signals = _signals(identity="b" * 64, session="c" * 64)
    for _ in range(2):
        write_event(
            action="register",
            decision=SecurityEvent.Decision.BLOCK,
            public_code="ANTIBOT_BLOCKED",
            reasons=("redis_outage",),
            signals=signals,
            force=True,
        )
    assert SecurityEvent.objects.count() == 1

    assert audit_module._local_first_in_window("extra-1")
    assert audit_module._local_first_in_window("extra-2")
    with audit_module._local_dedupe_lock:
        assert len(audit_module._local_dedupe) == 2

    with audit_module._local_dedupe_lock:
        audit_module._local_dedupe.clear()


@pytest.mark.skipif(
    os.environ.get("TRIADCAPTCHA_TEST_REAL_REDIS") != "1",
    reason="requires a real Redis service",
)
def test_real_redis_deduplicates_forced_events_across_processes():
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    start = context.Event()
    results = context.Queue()
    token = f"process-{secrets.token_urlsafe(18)}"
    workers = [
        context.Process(target=_redis_dedupe_worker, args=(token, ready, start, results))
        for _ in range(2)
    ]

    for worker in workers:
        worker.start()
    for _ in workers:
        assert ready.get(timeout=10) is True
    start.set()
    observed = [results.get(timeout=10) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)

    assert all(not worker.is_alive() for worker in workers)
    assert all(worker.exitcode == 0 for worker in workers)
    assert observed.count(True) == 1
    assert observed.count(False) == 1
