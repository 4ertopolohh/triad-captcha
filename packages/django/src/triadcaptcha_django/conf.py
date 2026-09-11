from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from django.conf import settings as django_settings
from django.utils.module_loading import import_string


class ConfigurationPending(RuntimeError):
    """Raised by a runtime resolver while its persistent configuration is unavailable."""


def _setting(name: str, default: Any = None) -> Any:
    value = getattr(django_settings, name, None)
    if value is not None:
        return value
    return os.environ.get(name, default)


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _list(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return tuple(str(part).strip() for part in value if str(part).strip())


@dataclass(frozen=True)
class TriadCaptchaSettings:
    site_key: str
    hmac_secret: str
    identifier_hmac_secret: str
    redis_url: str
    redis_prefix: str
    redis_socket_timeout: float
    redis_max_connections: int
    redis_pool_timeout: float
    trusted_proxy_networks: tuple[str, ...]
    development_mode: bool
    context_cookie_name: str
    context_cookie_max_age: int
    context_cookie_secure: bool | None
    context_cookie_samesite: str
    max_payload_bytes: int
    max_metadata_bytes: int
    audit_allow_sample_rate: float


@dataclass(frozen=True)
class SettingsState:
    settings: TriadCaptchaSettings
    pending: bool = False
    error: str = ""


def get_default_settings() -> TriadCaptchaSettings:
    """Build settings from Django settings/environment without a runtime resolver."""

    secure_cookie = _setting("TRIADCAPTCHA_CONTEXT_COOKIE_SECURE", None)
    return TriadCaptchaSettings(
        site_key=str(_setting("TRIADCAPTCHA_SITE_KEY", "") or ""),
        hmac_secret=str(_setting("TRIADCAPTCHA_HMAC_SECRET", "") or ""),
        identifier_hmac_secret=str(_setting("TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET", "") or ""),
        redis_url=str(_setting("TRIADCAPTCHA_REDIS_URL", "") or ""),
        redis_prefix=str(_setting("TRIADCAPTCHA_REDIS_PREFIX", "triadcaptcha") or "triadcaptcha"),
        redis_socket_timeout=max(
            0.05, _float(_setting("TRIADCAPTCHA_REDIS_SOCKET_TIMEOUT", 0.5), 0.5)
        ),
        redis_max_connections=_int(
            _setting("TRIADCAPTCHA_REDIS_MAX_CONNECTIONS", 32), 32
        ),
        redis_pool_timeout=_float(
            _setting("TRIADCAPTCHA_REDIS_POOL_TIMEOUT", 0.25), 0.25
        ),
        trusted_proxy_networks=_list(_setting("TRIADCAPTCHA_TRUSTED_PROXY_NETWORKS", ())),
        development_mode=_bool(_setting("TRIADCAPTCHA_DEVELOPMENT_MODE", False)),
        context_cookie_name=str(
            _setting("TRIADCAPTCHA_CONTEXT_COOKIE_NAME", "triadcaptcha_context")
        ),
        context_cookie_max_age=max(
            300, _int(_setting("TRIADCAPTCHA_CONTEXT_COOKIE_MAX_AGE", 86400), 86400)
        ),
        context_cookie_secure=None if secure_cookie is None else _bool(secure_cookie),
        context_cookie_samesite=str(
            _setting("TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE", "Lax") or "Lax"
        ).title(),
        max_payload_bytes=max(1024, _int(_setting("TRIADCAPTCHA_MAX_PAYLOAD_BYTES", 16384), 16384)),
        max_metadata_bytes=max(128, _int(_setting("TRIADCAPTCHA_MAX_METADATA_BYTES", 2048), 2048)),
        audit_allow_sample_rate=min(
            1.0,
            max(0.0, _float(_setting("TRIADCAPTCHA_AUDIT_ALLOW_SAMPLE_RATE", 0.05), 0.05)),
        ),
    )


def _pending_settings() -> TriadCaptchaSettings:
    defaults = get_default_settings()
    return TriadCaptchaSettings(
        site_key="",
        hmac_secret="",
        identifier_hmac_secret="",
        redis_url="",
        redis_prefix=defaults.redis_prefix,
        redis_socket_timeout=defaults.redis_socket_timeout,
        redis_max_connections=defaults.redis_max_connections,
        redis_pool_timeout=defaults.redis_pool_timeout,
        trusted_proxy_networks=defaults.trusted_proxy_networks,
        development_mode=False,
        context_cookie_name=defaults.context_cookie_name,
        context_cookie_max_age=defaults.context_cookie_max_age,
        context_cookie_secure=defaults.context_cookie_secure,
        context_cookie_samesite=defaults.context_cookie_samesite,
        max_payload_bytes=defaults.max_payload_bytes,
        max_metadata_bytes=defaults.max_metadata_bytes,
        audit_allow_sample_rate=defaults.audit_allow_sample_rate,
    )


def _coerce_resolved_settings(value: Any) -> TriadCaptchaSettings:
    if isinstance(value, TriadCaptchaSettings):
        return value
    if isinstance(value, Mapping):
        defaults = get_default_settings()
        merged = {field: getattr(defaults, field) for field in defaults.__dataclass_fields__}
        merged.update(value)
        return TriadCaptchaSettings(**merged)
    raise TypeError("TriadCAPTCHA settings resolver must return TriadCaptchaSettings or a mapping.")


def get_settings_state() -> SettingsState:
    """Resolve the current configuration, including database-backed runtime loaders."""

    resolver = getattr(django_settings, "TRIADCAPTCHA_SETTINGS_RESOLVER", None)
    if not resolver:
        return SettingsState(get_default_settings())
    try:
        if isinstance(resolver, str):
            resolver = import_string(resolver)
        if not callable(resolver):
            raise TypeError("TRIADCAPTCHA_SETTINGS_RESOLVER must be callable or a dotted path.")
        return SettingsState(_coerce_resolved_settings(resolver()))
    except ConfigurationPending as exc:
        return SettingsState(_pending_settings(), pending=True, error=str(exc))
    except Exception as exc:  # fail closed; the system check exposes the resolver failure
        return SettingsState(
            _pending_settings(),
            pending=True,
            error=f"{exc.__class__.__name__}: {exc}",
        )


def get_settings() -> TriadCaptchaSettings:
    return get_settings_state().settings


def secret_is_acceptable(value: str) -> bool:
    lowered = value.casefold()
    return bool(
        len(value.encode("utf-8")) >= 32
        and "change_me" not in lowered
        and "changeme" not in lowered
        and len(set(value)) >= 8
    )


def site_key_is_configured(value: str) -> bool:
    lowered = value.casefold()
    return bool(
        16 <= len(value) <= 96
        and re.fullmatch(r"[A-Za-z0-9._:-]+", value)
        and "change_me" not in lowered
        and "changeme" not in lowered
    )


def redis_url_is_valid(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme in {"redis", "rediss"}:
        return bool(parsed.hostname)
    if parsed.scheme == "unix":
        return bool(parsed.path)
    return False
