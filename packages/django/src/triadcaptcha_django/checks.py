from __future__ import annotations

import ipaddress

import django
from django.conf import settings as django_settings
from django.core.checks import Error, Tags, Warning, register

from .conf import (
    get_settings_state,
    redis_url_is_valid,
    secret_is_acceptable,
    site_key_is_configured,
)


@register(Tags.security)
def triadcaptcha_configuration_check(app_configs, **kwargs):
    state = get_settings_state()
    config = state.settings
    messages = []

    if state.pending:
        messages.append(
            Warning(
                "TriadCAPTCHA runtime configuration is pending.",
                hint=(
                    state.error
                    or "Complete the runtime configuration before enabling protection."
                ),
                id="triadcaptcha.W002",
            )
        )
        return messages

    if not secret_is_acceptable(config.hmac_secret):
        messages.append(
            Error(
                "TRIADCAPTCHA_HMAC_SECRET must contain at least 32 UTF-8 bytes.",
                id="triadcaptcha.E001",
            )
        )
    if not secret_is_acceptable(config.identifier_hmac_secret):
        messages.append(
            Error(
                "TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET must contain at least 32 UTF-8 bytes.",
                id="triadcaptcha.E002",
            )
        )
    if config.hmac_secret and config.hmac_secret == config.identifier_hmac_secret:
        messages.append(
            Error(
                "Challenge and identifier HMAC secrets must be different.",
                id="triadcaptcha.E003",
            )
        )
    if not site_key_is_configured(config.site_key):
        messages.append(
            Error(
                "TRIADCAPTCHA_SITE_KEY must be a non-empty public installation identifier.",
                id="triadcaptcha.E004",
            )
        )

    if not redis_url_is_valid(config.redis_url):
        messages.append(
            Error(
                "TRIADCAPTCHA_REDIS_URL must use redis://, rediss://, or unix://.",
                id="triadcaptcha.E005",
            )
        )
    if not 1 <= config.redis_max_connections <= 1024:
        messages.append(
            Error(
                "TRIADCAPTCHA_REDIS_MAX_CONNECTIONS must be between 1 and 1024.",
                id="triadcaptcha.E008",
            )
        )
    if not 0.01 <= config.redis_pool_timeout <= 30:
        messages.append(
            Error(
                "TRIADCAPTCHA_REDIS_POOL_TIMEOUT must be between 0.01 and 30 seconds.",
                id="triadcaptcha.E009",
            )
        )

    for network in config.trusted_proxy_networks:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            messages.append(
                Error(
                    f"Invalid trusted proxy network: {network!r}.",
                    id="triadcaptcha.E006",
                )
            )

    if config.development_mode and not django_settings.DEBUG:
        messages.append(
            Error(
                "TRIADCAPTCHA_DEVELOPMENT_MODE cannot be enabled while DEBUG is false.",
                id="triadcaptcha.E007",
            )
        )
    if config.development_mode:
        messages.append(
            Warning(
                "TriadCAPTCHA development mode is enabled.",
                hint="Disable it before deploying.",
                id="triadcaptcha.W001",
            )
        )
    if config.context_cookie_samesite not in {"Strict", "Lax", "None"}:
        messages.append(
            Error(
                "TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE must be Strict, Lax, or None.",
                id="triadcaptcha.E010",
            )
        )
    if (
        config.context_cookie_samesite == "None"
        and config.context_cookie_secure is not True
    ):
        messages.append(
            Error(
                "SameSite=None requires TRIADCAPTCHA_CONTEXT_COOKIE_SECURE=true.",
                id="triadcaptcha.E011",
            )
        )
    if not django_settings.DEBUG and django.VERSION[:2] < (5, 2):
        messages.append(
            Warning(
                "This Django release is no longer supported for production use.",
                hint="Use Django 5.2 or newer; 4.2 is retained only for legacy compatibility.",
                id="triadcaptcha.W003",
            )
        )
    return messages
