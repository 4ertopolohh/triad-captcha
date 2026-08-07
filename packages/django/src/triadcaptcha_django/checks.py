from __future__ import annotations

import ipaddress

from django.conf import settings as django_settings
from django.core.checks import Error, Tags, Warning, register

from .conf import (
    get_settings,
    redis_url_is_valid,
    secret_is_acceptable,
    site_key_is_configured,
)


@register(Tags.security)
def triadcaptcha_configuration_check(app_configs, **kwargs):
    config = get_settings()
    messages = []

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
    return messages
