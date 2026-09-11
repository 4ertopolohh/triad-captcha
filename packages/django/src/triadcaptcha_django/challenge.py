from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from altcha import Payload, create_challenge, verify_solution

from .audit import AuditSignals, write_event
from .conf import get_settings, site_key_is_configured
from .errors import ErrorCode, TriadCaptchaFailure
from .models import ProtectedAction, SecurityEvent
from .redis_backend import (
    consume_attempt_challenge,
    get_attempt,
    increment,
    issue_attempt_challenge,
    key,
)
from .signals import get_context_binding, hash_ip, normalize_user_agent
from .site_keys import (
    accepted_site_key_markers,
    current_site_key,
    site_key_is_accepted,
    site_key_marker,
)

JTI_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
ATTEMPT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


@dataclass(frozen=True)
class ChallengeEnvelope:
    challenge: dict[str, Any]
    action: str
    site_key: str
    expires_at: int
    context_cookie: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge,
            "action": self.action,
            "site_key": self.site_key,
            "expires_at": self.expires_at,
        }


def _derived_key_secret() -> bytes:
    return hmac.new(
        get_settings().hmac_secret.encode("utf-8"),
        b"triadcaptcha:altcha-derived-key:v1",
        hashlib.sha256,
    ).digest()


def _marker(action: str, context_hash: str, key_marker: str) -> str:
    return f"{action}|{context_hash}|{key_marker}"


def _payload_dict(payload: str) -> dict[str, Any]:
    try:
        if len(payload.encode("utf-8")) > get_settings().max_payload_bytes:
            raise ValueError("payload too large")
        decoded = base64.b64decode(payload, validate=True)
        if len(decoded) > get_settings().max_payload_bytes:
            raise ValueError("payload too large")
        data = json.loads(decoded.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("payload root is not an object")
        return data
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="payload_parse_failed"
        ) from exc


def issue_challenge(request, policy: ProtectedAction) -> ChallengeEnvelope:
    supplied_site_key = request.headers.get("X-TriadCAPTCHA-Site-Key")
    attempt_token = request.headers.get("X-TriadCAPTCHA-Attempt", "")
    if not supplied_site_key or not site_key_is_configured(supplied_site_key):
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="site_key_malformed")
    if not ATTEMPT_PATTERN.fullmatch(attempt_token):
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="attempt_malformed")
    ip_hash = hash_ip(request)
    window = policy.rate_window_seconds
    ip_rate = increment(key("issue-precheck", policy.action, "ip", ip_hash), window)
    if ip_rate.count > policy.challenge_issue_limit:
        raise TriadCaptchaFailure(
            ErrorCode.RATE_LIMITED,
            retry_after=max(ip_rate.ttl, 1),
            internal_reason="challenge_issue_rate_limit",
        )
    if not site_key_is_accepted(supplied_site_key):
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="site_key_mismatch")
    requested_site = site_key_marker(supplied_site_key)
    attempt = get_attempt(attempt_token)
    if (
        attempt is None
        or attempt.state != "pending"
        or attempt.action != policy.action
        or attempt.requested_site != requested_site
    ):
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="attempt_mismatch")

    # Allocate a session/technical context only after the IP issuance ceiling has
    # passed. Otherwise a cookie-less flood could create an unbounded number of
    # Django database sessions even though every response is already rate-limited.
    context = get_context_binding(request, create=True)
    if not context.context_hash:
        raise TriadCaptchaFailure(
            ErrorCode.CONFIGURATION_ERROR, internal_reason="context_binding_unavailable"
        )
    accepted_ip_rate = increment(key("issue", policy.action, "ip", ip_hash), window)
    session_rate = increment(key("issue", policy.action, "session", context.context_hash), window)
    if (
        accepted_ip_rate.count > policy.challenge_issue_limit
        or session_rate.count > policy.challenge_issue_limit
    ):
        raise TriadCaptchaFailure(
            ErrorCode.RATE_LIMITED,
            retry_after=max(accepted_ip_rate.ttl, session_rate.ttl, 1),
            internal_reason="challenge_issue_rate_limit",
        )

    site_key = current_site_key()
    if not site_key:
        raise TriadCaptchaFailure(ErrorCode.CONFIGURATION_ERROR, internal_reason="site_key_missing")
    expires_at = int(time.time()) + policy.challenge_ttl_seconds
    jti = secrets.token_urlsafe(24)
    marker = _marker(policy.action, context.context_hash, site_key_marker(site_key))
    issued = issue_attempt_challenge(
        attempt_token,
        action=policy.action,
        requested_site=requested_site,
        context_hash=context.context_hash,
        jti=jti,
        marker=marker,
        challenge_site=site_key_marker(site_key),
        challenge_ttl=policy.challenge_ttl_seconds,
        attempt_ttl=policy.challenge_ttl_seconds + 60,
    )
    if issued != 1:
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD if issued in {0, -1} else ErrorCode.SERVICE_UNAVAILABLE,
            internal_reason=(
                "attempt_mismatch" if issued in {0, -1} else "challenge_jti_collision"
            ),
        )

    counter = secrets.randbelow(policy.pow_max_counter - policy.pow_min_counter + 1)
    counter += policy.pow_min_counter
    challenge = create_challenge(
        algorithm=policy.pow_algorithm,
        cost=policy.pow_cost,
        counter=counter,
        expires_at=datetime.fromtimestamp(expires_at, tz=timezone.utc),
        data={
            "jti": jti,
            "action": policy.action,
            "siteKey": site_key_marker(site_key),
            "issuedAt": int(time.time()),
        },
        hmac_secret=get_settings().hmac_secret,
        hmac_key_secret=_derived_key_secret(),
    )
    write_event(
        action=policy.action,
        decision=SecurityEvent.Decision.CHALLENGE_ISSUED,
        reasons=("adaptive_challenge_issued",),
        signals=AuditSignals(
            ip_hash=ip_hash,
            session_hash=context.context_hash,
            user_agent_family=normalize_user_agent(request),
        ),
        force=True,
    )
    return ChallengeEnvelope(
        challenge=challenge.to_dict(),
        action=policy.action,
        site_key=site_key,
        expires_at=expires_at,
        context_cookie=context.cookie_value,
    )


def verify_and_consume(
    request,
    policy: ProtectedAction,
    payload: str,
    attempt_token: str,
) -> None:
    raw = _payload_dict(payload)
    try:
        result = verify_solution(
            payload,
            get_settings().hmac_secret,
            hmac_key_secret=_derived_key_secret(),
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        # altcha validates the signed challenge, but malformed solution scalar
        # types/hex can fail while it constructs the derived-key bytes.
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="altcha_invalid_structure"
        ) from exc
    if result.expired:
        raise TriadCaptchaFailure(ErrorCode.CHALLENGE_EXPIRED, internal_reason="altcha_expired")
    if not result.verified:
        reason = "altcha_invalid_solution"
        if result.invalid_signature:
            reason = "altcha_invalid_signature"
        elif result.error:
            reason = "altcha_invalid_structure"
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason=reason)

    try:
        parsed = Payload.from_dict(raw)
        parameters = parsed.challenge.parameters
        solution = parsed.solution
        data = parameters.data
        if not isinstance(data, dict):
            raise ValueError("missing signed data")
        jti = data.get("jti")
        signed_action = data.get("action")
        signed_site_key = data.get("siteKey")
        if not isinstance(jti, str) or not JTI_PATTERN.fullmatch(jti):
            raise ValueError("invalid jti")
        if not isinstance(solution.counter, int) or isinstance(solution.counter, bool):
            raise ValueError("invalid counter")
        if solution.counter < 0 or solution.counter > policy.pow_max_counter:
            raise ValueError("counter outside policy")
        if parameters.algorithm != policy.pow_algorithm or parameters.cost != policy.pow_cost:
            raise ValueError("proof policy mismatch")
        if len(solution.derived_key) != parameters.key_length * 2:
            raise ValueError("invalid derived key length")
        if (
            not isinstance(parameters.key_prefix, str)
            or len(parameters.key_prefix) != 32
            or not re.fullmatch(r"[0-9a-f]{32}", parameters.key_prefix)
            or not solution.derived_key.startswith(parameters.key_prefix)
        ):
            # Defence in depth for deterministic challenges and for the
            # keyPrefix fallback issue fixed upstream in altcha 2.1.0.
            raise ValueError("invalid deterministic key prefix")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="signed_data_invalid"
        ) from exc

    context = get_context_binding(request, create=False)
    if not context.context_hash:
        raise TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="context_missing")
    if not secrets.compare_digest(str(signed_action), policy.action):
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="action_binding_mismatch"
        )
    accepted_markers = list(accepted_site_key_markers())
    candidate_keys = [current_site_key()]
    supplied_site_key = request.headers.get("X-TriadCAPTCHA-Site-Key")
    if supplied_site_key:
        candidate_keys.append(supplied_site_key)
    for candidate in candidate_keys:
        if candidate:
            accepted_markers.append(site_key_marker(candidate))
    if not any(secrets.compare_digest(str(signed_site_key), marker) for marker in accepted_markers):
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="site_key_binding_mismatch"
        )

    marker = _marker(policy.action, context.context_hash, str(signed_site_key))
    consume_result = consume_attempt_challenge(
        attempt_token, jti, marker, policy.challenge_ttl_seconds + 60
    )
    if consume_result == 2:
        raise TriadCaptchaFailure(ErrorCode.CHALLENGE_REPLAYED, internal_reason="challenge_replay")
    if consume_result == 0:
        raise TriadCaptchaFailure(
            ErrorCode.CHALLENGE_EXPIRED, internal_reason="challenge_state_missing"
        )
    if consume_result == -1:
        # The context binding is kept exclusively in the server-side Redis
        # reservation. It is intentionally absent from the browser payload.
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="session_binding_mismatch"
        )
    if consume_result != 1:
        raise TriadCaptchaFailure(
            ErrorCode.INVALID_PAYLOAD, internal_reason="challenge_state_mismatch"
        )
