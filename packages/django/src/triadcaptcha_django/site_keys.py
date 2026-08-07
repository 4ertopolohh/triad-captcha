from __future__ import annotations

import hashlib
import secrets

from django.db.models import Q
from django.utils import timezone

from .conf import get_settings
from .models import SiteKeyVersion


def _accepted_database_keys() -> list[str]:
    now = timezone.now()
    return list(
        SiteKeyVersion.objects.filter(
            status__in=(SiteKeyVersion.Status.ACTIVE, SiteKeyVersion.Status.GRACE),
            not_before__lte=now,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .values_list("site_key", flat=True)
    )


def current_site_key() -> str:
    now = timezone.now()
    current = (
        SiteKeyVersion.objects.filter(
            status=SiteKeyVersion.Status.ACTIVE,
            not_before__lte=now,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-created_at")
        .values_list("site_key", flat=True)
        .first()
    )
    if current:
        return current
    # Once versioned keys exist, database status is authoritative. Falling back
    # to the environment here would silently undo an explicit revocation.
    return "" if SiteKeyVersion.objects.exists() else get_settings().site_key


def site_key_is_accepted(candidate: str | None) -> bool:
    if not candidate:
        return False
    accepted = _accepted_database_keys()
    if not accepted and not SiteKeyVersion.objects.exists():
        accepted = [get_settings().site_key]
    return any(secrets.compare_digest(str(candidate), key) for key in accepted if key)


def site_key_marker(site_key: str) -> str:
    return hashlib.sha256(site_key.encode("utf-8")).hexdigest()[:24]


def accepted_site_key_markers() -> tuple[str, ...]:
    keys = _accepted_database_keys()
    if not keys and not SiteKeyVersion.objects.exists():
        keys = [get_settings().site_key]
    return tuple(site_key_marker(value) for value in keys if value)
