from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .audit import AuditSignals, write_event
from .challenge import issue_challenge
from .conf import (
    get_settings,
    redis_url_is_valid,
    secret_is_acceptable,
    site_key_is_configured,
)
from .errors import ErrorCode, TriadCaptchaFailure
from .models import ProtectedAction, ProtectionConfiguration, SecurityEvent
from .redis_backend import RedisUnavailable
from .signals import (
    get_context_binding,
    hash_ip,
    normalize_user_agent,
    set_context_cookie,
    validate_action,
)


def _audit_error(request, action: str, failure: TriadCaptchaFailure) -> None:
    signals = AuditSignals()
    try:
        config = get_settings()
        if secret_is_acceptable(config.hmac_secret) and secret_is_acceptable(
            config.identifier_hmac_secret
        ):
            context = get_context_binding(request, create=False)
            signals = AuditSignals(
                ip_hash=hash_ip(request),
                session_hash=context.context_hash,
                user_agent_family=normalize_user_agent(request),
            )
    except Exception:
        # The original public failure must not be replaced by an audit-signal
        # collection problem (for example, a malformed proxy-network setting).
        signals = AuditSignals()
    write_event(
        action=action,
        decision=SecurityEvent.Decision.BLOCK,
        public_code=failure.public_error.code.value,
        reasons=(failure.internal_reason,),
        signals=signals,
        force=True,
    )


def _failure_response(request, action: str, failure: TriadCaptchaFailure) -> JsonResponse:
    _audit_error(request, action, failure)
    return failure.public_error.response()


@never_cache
@require_GET
def challenge_view(request):
    action = "invalid"
    try:
        action = validate_action(request.GET.get("action", ""))
        header_action = request.headers.get("X-TriadCAPTCHA-Action")
        if header_action and header_action != action:
            raise TriadCaptchaFailure(
                ErrorCode.INVALID_PAYLOAD, internal_reason="action_header_mismatch"
            )
        config = get_settings()
        if (
            not secret_is_acceptable(config.hmac_secret)
            or not secret_is_acceptable(config.identifier_hmac_secret)
            or config.hmac_secret == config.identifier_hmac_secret
            or not redis_url_is_valid(config.redis_url)
            or not site_key_is_configured(config.site_key)
        ):
            raise TriadCaptchaFailure(
                ErrorCode.CONFIGURATION_ERROR, internal_reason="invalid_runtime_configuration"
            )

        global_config = ProtectionConfiguration.objects.filter(pk=1).first()
        if global_config is not None and not global_config.enabled:
            raise TriadCaptchaFailure(
                ErrorCode.CONFIGURATION_ERROR, internal_reason="protection_disabled"
            )
        policy = ProtectedAction.objects.get(action=action, enabled=True)
        envelope = issue_challenge(request, policy)
        response = JsonResponse(envelope.as_dict())
        response["Cache-Control"] = "no-store"
        response["Vary"] = "Cookie"
        set_context_cookie(response, envelope.context_cookie, request)
        return response
    except ValueError:
        return _failure_response(
            request,
            "invalid",
            TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="invalid_action"),
        )
    except ProtectedAction.DoesNotExist:
        return _failure_response(
            request,
            action,
            TriadCaptchaFailure(ErrorCode.INVALID_PAYLOAD, internal_reason="unknown_action"),
        )
    except TriadCaptchaFailure as exc:
        return _failure_response(request, action, exc)
    except RedisUnavailable:
        return _failure_response(
            request,
            action,
            TriadCaptchaFailure(
                ErrorCode.SERVICE_UNAVAILABLE, internal_reason="redis_unavailable"
            ),
        )
    except Exception:
        return _failure_response(
            request,
            action,
            TriadCaptchaFailure(
                ErrorCode.SERVICE_UNAVAILABLE, internal_reason="challenge_internal_failure"
            ),
        )
