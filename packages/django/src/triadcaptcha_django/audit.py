from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .conf import get_settings
from .models import ProtectionConfiguration, SecurityEvent
from .redis_backend import increment, key
from .signals import safe_metadata_for_audit

logger = logging.getLogger(__name__)
_DEDUPE_WINDOW_SECONDS = 60
_LOCAL_DEDUPE_LIMIT = 4096
_local_dedupe: OrderedDict[str, float] = OrderedDict()
_local_dedupe_lock = threading.Lock()


@dataclass(frozen=True)
class AuditSignals:
    ip_hash: str = ""
    identity_hash: str = ""
    session_hash: str = ""
    ip_identity_hash: str = ""
    user_agent_family: str = ""


def _allow_sample_rate() -> float:
    configured = (
        ProtectionConfiguration.objects.filter(pk=1)
        .values_list("allow_audit_sample_rate", flat=True)
        .first()
    )
    if configured is None:
        return get_settings().audit_allow_sample_rate
    return min(1.0, max(0.0, float(configured)))


def _dedupe_token(
    *,
    action: str,
    decision: str,
    public_code: str,
    reasons: tuple[str, ...] | list[str],
    signals: AuditSignals,
) -> str:
    binding = (
        signals.ip_hash
        or signals.ip_identity_hash
        or signals.session_hash
        or signals.identity_hash
        or "unbound"
    )
    material = "\x1f".join((action, decision, public_code, *reasons, binding))
    return sha256(material.encode("utf-8")).hexdigest()[:32]


def _local_first_in_window(token: str) -> bool:
    now = time.monotonic()
    with _local_dedupe_lock:
        while _local_dedupe:
            oldest, expires_at = next(iter(_local_dedupe.items()))
            if expires_at > now:
                break
            _local_dedupe.pop(oldest, None)
        if _local_dedupe.get(token, 0) > now:
            return False
        if len(_local_dedupe) >= _LOCAL_DEDUPE_LIMIT:
            _local_dedupe.popitem(last=False)
        _local_dedupe[token] = now + _DEDUPE_WINDOW_SECONDS
        return True


def _first_forced_event_in_window(token: str) -> bool:
    try:
        value = increment(key("audit-dedupe", token), _DEDUPE_WINDOW_SECONDS)
        return value.count == 1
    except Exception:
        # Audit must not replace the enforcement response during a Redis outage.
        # A bounded process-local fallback still prevents one client from
        # amplifying a database outage event on every request.
        return _local_first_in_window(token)


def write_event(
    *,
    action: str,
    decision: str,
    public_code: str = "",
    risk_score: int = 0,
    reasons: tuple[str, ...] | list[str] = (),
    signals: AuditSignals | None = None,
    metadata: Mapping[str, Any] | None = None,
    force: bool = False,
) -> None:
    """Best-effort audit write. No raw identifiers or payloads are accepted."""

    try:
        signals = signals or AuditSignals()
        if force:
            token = _dedupe_token(
                action=action,
                decision=decision,
                public_code=public_code,
                reasons=reasons,
                signals=signals,
            )
            if not _first_forced_event_in_window(token):
                return
        else:
            if secrets.randbelow(1_000_000) >= int(_allow_sample_rate() * 1_000_000):
                return
        SecurityEvent.objects.create(
            action=action,
            decision=decision,
            public_code=public_code,
            risk_score=min(100, max(0, int(risk_score))),
            reason_codes=list(reasons)[:32],
            ip_hash=signals.ip_hash,
            identity_hash=signals.identity_hash,
            session_hash=signals.session_hash,
            ip_identity_hash=signals.ip_identity_hash,
            user_agent_family=signals.user_agent_family,
            safe_metadata=safe_metadata_for_audit(metadata or {}),
        )
    except Exception:
        # Audit storage must not turn a successfully enforced decision into an outage.
        # The exception is deliberately logged without request data.
        logger.exception("TriadCAPTCHA audit write failed")
