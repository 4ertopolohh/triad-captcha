from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from django.conf import settings as django_settings
from django.http.request import RawPostDataException

from .audit import write_event
from .challenge import verify_and_consume
from .conf import (
    get_settings,
    redis_url_is_valid,
    secret_is_acceptable,
    site_key_is_configured,
)
from .errors import ErrorCode, TriadCaptchaFailure
from .models import ProtectedAction, ProtectionConfiguration, SecurityEvent
from .redis_backend import RedisUnavailable, delete, increment
from .risk import (
    RequestSignals,
    assess_risk,
    collect_signals,
    create_temporary_block,
    failure_keys,
    replay_key,
)
from .signals import decode_metadata_header, sanitize_metadata, validate_action
from .site_keys import site_key_is_accepted
from .types import EvaluationResult, allow, block, challenge_required


def _configuration_is_valid() -> bool:
    config = get_settings()
    return bool(
        secret_is_acceptable(config.hmac_secret)
        and secret_is_acceptable(config.identifier_hmac_secret)
        and config.hmac_secret != config.identifier_hmac_secret
        and site_key_is_configured(config.site_key)
        and redis_url_is_valid(config.redis_url)
    )


def _extract_payload(request, explicit: Any) -> str | None:
    value = explicit
    if value is None:
        value = request.headers.get("X-TriadCAPTCHA-Payload")
    if value is None and request.method not in {"GET", "HEAD", "OPTIONS"}:
        content_type = request.content_type or ""
        if content_type.startswith("application/json"):
            try:
                if len(request.body) <= get_settings().max_payload_bytes * 4:
                    body = json.loads(request.body.decode(request.encoding or "utf-8") or "{}")
                    if isinstance(body, dict):
                        value = body.get("_triadcaptcha", body.get("triadcaptcha"))
            except (RawPostDataException, UnicodeDecodeError, json.JSONDecodeError):
                pass
        elif hasattr(request, "POST"):
            value = request.POST.get("_triadcaptcha") or request.POST.get("triadcaptcha")
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError("payload must be a string")
    if len(value.encode("utf-8")) > get_settings().max_payload_bytes:
        raise ValueError("payload too large")
    return value


def _extract_metadata(request, explicit: Mapping[str, Any] | None) -> dict[str, Any]:
    if explicit is not None:
        return sanitize_metadata(explicit)
    encoded = request.headers.get("X-TriadCAPTCHA-Metadata", "")
    return sanitize_metadata(decode_metadata_header(encoded)) if encoded else {}


def _result_with_audit(
    result: EvaluationResult,
    *,
    action: str,
    signals: RequestSignals | None,
    metadata: dict,
) -> EvaluationResult:
    decision = (
        SecurityEvent.Decision.ALLOW
        if result.allowed
        else SecurityEvent.Decision.CHALLENGE
        if result.decision.value == "challenge_required"
        else SecurityEvent.Decision.BLOCK
    )
    write_event(
        action=action,
        decision=decision,
        public_code=result.code or "",
        risk_score=result.risk_score,
        reasons=result.reasons,
        signals=signals.audit() if signals else None,
        metadata=metadata,
        force=not result.allowed,
    )
    return result


def evaluate(
    request,
    action: str,
    identity: Any = None,
    payload: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EvaluationResult:
    """Evaluate a protected request before its business operation runs."""

    signals: RequestSignals | None = None
    safe_metadata: dict[str, Any] = {}
    try:
        action = validate_action(action)
        if not _configuration_is_valid():
            return _result_with_audit(
                block(ErrorCode.CONFIGURATION_ERROR, reasons=("invalid_runtime_configuration",)),
                action=action,
                signals=None,
                metadata={},
            )

        header_action = request.headers.get("X-TriadCAPTCHA-Action")
        if header_action and header_action != action:
            return _result_with_audit(
                block(ErrorCode.INVALID_PAYLOAD, reasons=("action_header_mismatch",)),
                action=action,
                signals=None,
                metadata={},
            )
        if not site_key_is_accepted(request.headers.get("X-TriadCAPTCHA-Site-Key")):
            return _result_with_audit(
                block(ErrorCode.INVALID_PAYLOAD, reasons=("site_key_mismatch",)),
                action=action,
                signals=None,
                metadata={},
            )

        configuration = ProtectionConfiguration.objects.filter(pk=1).first()
        if configuration is None:
            configuration = ProtectionConfiguration()
        try:
            policy = ProtectedAction.objects.get(action=action)
        except ProtectedAction.DoesNotExist:
            return _result_with_audit(
                block(ErrorCode.CONFIGURATION_ERROR, reasons=("unknown_action",)),
                action=action,
                signals=None,
                metadata={},
            )

        if not configuration.enabled or not policy.enabled:
            return allow(reasons=("protection_disabled",))
        if (
            configuration.development_mode
            and get_settings().development_mode
            and django_settings.DEBUG
        ):
            return _result_with_audit(
                allow(reasons=("development_mode",)),
                action=action,
                signals=None,
                metadata={},
            )

        safe_metadata = _extract_metadata(request, metadata)
        supplied_payload = _extract_payload(request, payload)
        signals = collect_signals(request, identity)
        try:
            assessment = assess_risk(policy, signals, safe_metadata)
        except RedisUnavailable:
            # A supplied proof must never bypass cryptographic verification or
            # one-time consumption, even for explicitly low-impact fail-open actions.
            if policy.fail_closed or supplied_payload:
                return _result_with_audit(
                    block(
                        ErrorCode.SERVICE_UNAVAILABLE,
                        reasons=("redis_unavailable",),
                    ),
                    action=action,
                    signals=signals,
                    metadata=safe_metadata,
                )
            return _result_with_audit(
                allow(reasons=("redis_unavailable_fail_open",)),
                action=action,
                signals=signals,
                metadata=safe_metadata,
            )

        if assessment.should_block:
            retry_after = assessment.retry_after
            if not assessment.existing_block:
                try:
                    retry_after = create_temporary_block(policy, signals, assessment.reasons)
                except RedisUnavailable:
                    if policy.fail_closed:
                        return _result_with_audit(
                            block(
                                ErrorCode.SERVICE_UNAVAILABLE,
                                reasons=assessment.reasons + ("block_store_unavailable",),
                            ),
                            action=action,
                            signals=signals,
                            metadata=safe_metadata,
                        )
            return _result_with_audit(
                block(
                    ErrorCode.BLOCKED,
                    retry_after=retry_after,
                    risk_score=assessment.score,
                    reasons=assessment.reasons,
                ),
                action=action,
                signals=signals,
                metadata=safe_metadata,
            )

        if supplied_payload:
            try:
                verify_and_consume(request, policy, supplied_payload)
            except RedisUnavailable:
                return _result_with_audit(
                    block(
                        ErrorCode.SERVICE_UNAVAILABLE,
                        risk_score=assessment.score,
                        reasons=assessment.reasons + ("challenge_consume_unavailable",),
                    ),
                    action=action,
                    signals=signals,
                    metadata=safe_metadata,
                )
            except TriadCaptchaFailure as exc:
                if exc.public_error.code is ErrorCode.CHALLENGE_REPLAYED:
                    try:
                        increment(
                            replay_key(policy, signals), max(600, policy.rate_window_seconds * 10)
                        )
                    except RedisUnavailable:
                        pass
                return _result_with_audit(
                    block(
                        exc.public_error.code,
                        status=exc.public_error.status,
                        retry_after=exc.public_error.retry_after,
                        risk_score=assessment.score,
                        reasons=assessment.reasons + (exc.internal_reason,),
                    ),
                    action=action,
                    signals=signals,
                    metadata=safe_metadata,
                )
            return _result_with_audit(
                allow(
                    risk_score=assessment.score,
                    reasons=assessment.reasons + ("challenge_verified",),
                ),
                action=action,
                signals=signals,
                metadata=safe_metadata,
            )

        if assessment.score >= policy.challenge_threshold:
            return _result_with_audit(
                challenge_required(risk_score=assessment.score, reasons=assessment.reasons),
                action=action,
                signals=signals,
                metadata=safe_metadata,
            )
        return _result_with_audit(
            allow(risk_score=assessment.score, reasons=assessment.reasons),
            action=action,
            signals=signals,
            metadata=safe_metadata,
        )
    except (ValueError, TypeError, UnicodeError):
        return _result_with_audit(
            block(ErrorCode.INVALID_PAYLOAD, reasons=("invalid_request_contract",)),
            action="invalid",
            signals=signals,
            metadata=safe_metadata,
        )
    except Exception:
        # Database/configuration errors fail closed without disclosing internals.
        return _result_with_audit(
            block(ErrorCode.SERVICE_UNAVAILABLE, reasons=("service_internal_failure",)),
            action="invalid",
            signals=signals,
            metadata=safe_metadata,
        )


def record_outcome(
    request,
    action: str,
    identity: Any = None,
    *,
    outcome: str,
) -> None:
    """Record a server-observed outcome; never pass passwords or one-time codes."""

    action = validate_action(action)
    allowed = {"success", "password_failure", "code_failure", "business_rejection"}
    if outcome not in allowed:
        raise ValueError(f"Unsupported outcome: {outcome}")
    policy = ProtectedAction.objects.get(action=action)
    signals = collect_signals(request, identity)
    keys = failure_keys(policy, signals)
    redis_available = True
    try:
        if outcome == "success":
            delete(*keys)
        else:
            window = min(86400, max(600, policy.rate_window_seconds * 10))
            for item in keys:
                increment(item, window)
    except RedisUnavailable:
        # This helper is commonly called after the business operation. Raising
        # now could turn a committed success into a 500 and invite a duplicate
        # client retry. The next protected evaluate still fails closed while
        # Redis is unavailable; record the loss of this supplemental signal.
        redis_available = False
    reasons = ["business_success" if outcome == "success" else outcome]
    if not redis_available:
        reasons.append("outcome_redis_unavailable")
    write_event(
        action=action,
        decision=SecurityEvent.Decision.OUTCOME,
        reasons=tuple(reasons),
        signals=signals.audit(),
        force=outcome != "success" or not redis_available,
    )
