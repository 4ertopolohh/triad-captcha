from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from django.core import signing

from .conf import get_settings

ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
METADATA_KEYS = {
    "form_fill_ms",
    "focus_count",
    "input_count",
    "pointer_count",
    "keyboard_count",
    "page_visible",
    "honeypot_filled",
    # Backward-compatible aliases; output is always canonicalized below.
    "focus_events",
    "input_events",
    "visibility_changes",
    "honeypot",
    "was_autofilled",
}


def validate_action(action: str) -> str:
    value = str(action or "").strip()
    if not ACTION_PATTERN.fullmatch(value):
        raise ValueError("invalid action")
    return value


def _hmac_hex(kind: str, value: str) -> str:
    secret = get_settings().identifier_hmac_secret.encode("utf-8")
    message = f"triadcaptcha:{kind}:v1:{value}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def normalize_identity(identity: Any) -> tuple[str, str]:
    if identity is None or identity == "":
        return "", ""
    kind = "generic"
    value: Any = identity
    if isinstance(identity, Mapping):
        if "value" in identity:
            kind = str(identity.get("type") or "generic").lower()
            value = identity.get("value")
        else:
            canonical_parts = []
            for original_key, original_value in sorted(
                identity.items(), key=lambda item: str(item[0]).casefold()
            ):
                key = str(original_key).casefold()
                canonical_parts.append(f"{key}={str(original_value).strip().casefold()}")
            return "compound", "|".join(canonical_parts)
    elif isinstance(identity, (tuple, list)) and len(identity) == 2:
        kind, value = str(identity[0]).lower(), identity[1]

    normalized = str(value or "").strip()
    if not normalized:
        return "", ""
    if kind == "email" or (kind == "generic" and "@" in normalized):
        kind = "email"
        normalized = normalized.casefold()
    elif kind in {"phone", "tel", "telephone"}:
        kind = "phone"
        leading_plus = normalized.startswith("+")
        normalized = re.sub(r"\D", "", normalized)
        normalized = ("+" if leading_plus else "") + normalized
    else:
        normalized = normalized.casefold()
    return kind, normalized


def hash_identity(identity: Any) -> str:
    kind, value = normalize_identity(identity)
    return _hmac_hex(f"identity:{kind}", value) if value else ""


def _parse_ip(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def get_client_ip(request) -> str:
    remote = _parse_ip(str(request.META.get("REMOTE_ADDR", "")))
    if not remote:
        return "unknown"
    trusted = [
        ipaddress.ip_network(item, strict=False) for item in get_settings().trusted_proxy_networks
    ]
    if not any(ipaddress.ip_address(remote) in network for network in trusted):
        return remote

    forwarded = [
        parsed
        for item in str(request.META.get("HTTP_X_FORWARDED_FOR", "")).split(",")
        if (parsed := _parse_ip(item))
    ]
    if not forwarded:
        return remote
    chain = forwarded + [remote]
    for candidate in reversed(chain):
        address = ipaddress.ip_address(candidate)
        if not any(address in network for network in trusted):
            return candidate
    return forwarded[0]


def hash_ip(request) -> str:
    return _hmac_hex("ip", get_client_ip(request))


def hash_pair(ip_hash: str, identity_hash: str) -> str:
    if not ip_hash or not identity_hash:
        return ""
    return _hmac_hex("ip-identity", f"{ip_hash}:{identity_hash}")


def normalize_user_agent(request) -> str:
    value = str(request.META.get("HTTP_USER_AGENT", ""))[:512].lower()
    families = (
        ("edge", ("edg/", "edge/")),
        ("chrome", ("chrome/", "crios/")),
        ("firefox", ("firefox/", "fxios/")),
        ("safari", ("safari/",)),
        ("curl", ("curl/",)),
        ("wget", ("wget/",)),
        ("bot", ("bot", "spider", "crawler")),
    )
    for family, needles in families:
        if any(needle in value for needle in needles):
            return family
    return "other" if value else "missing"


@dataclass(frozen=True)
class ContextBinding:
    context_hash: str
    cookie_value: str | None = None


def _context_signer():
    return signing.TimestampSigner(
        key=get_settings().hmac_secret,
        salt="triadcaptcha.context.v1",
        algorithm="sha256",
    )


def get_context_binding(request, *, create: bool = False) -> ContextBinding:
    session = getattr(request, "session", None)
    if session is not None:
        session_token = session.get("_triadcaptcha_context")
        if session_token:
            return ContextBinding(_hmac_hex("session", f"django-token:{session_token}"))
        session_key = session.session_key
        if session_key:
            return ContextBinding(_hmac_hex("session", f"django:{session_key}"))
        if create:
            session_token = secrets.token_urlsafe(32)
            session["_triadcaptcha_context"] = session_token
            return ContextBinding(_hmac_hex("session", f"django-token:{session_token}"))

    config = get_settings()
    signed_cookie = request.COOKIES.get(config.context_cookie_name, "")
    if signed_cookie:
        try:
            raw = _context_signer().unsign(signed_cookie, max_age=config.context_cookie_max_age)
            return ContextBinding(_hmac_hex("session", f"cookie:{raw}"))
        except signing.BadSignature:
            pass
    if not create:
        return ContextBinding("")
    raw = secrets.token_urlsafe(32)
    value = _context_signer().sign(raw)
    return ContextBinding(_hmac_hex("session", f"cookie:{raw}"), cookie_value=value)


def set_context_cookie(response, cookie_value: str | None, request) -> None:
    if not cookie_value:
        return
    config = get_settings()
    secure = (
        request.is_secure()
        if config.context_cookie_secure is None
        else config.context_cookie_secure
    )
    response.set_cookie(
        config.context_cookie_name,
        cookie_value,
        max_age=config.context_cookie_max_age,
        httponly=True,
        secure=secure,
        samesite=config.context_cookie_samesite,
        path="/",
    )


def decode_metadata_header(value: str) -> dict[str, Any]:
    config = get_settings()
    if not value:
        return {}
    if len(value.encode("utf-8")) > config.max_metadata_bytes * 2:
        raise ValueError("metadata too large")
    try:
        if value.lstrip().startswith("{"):
            decoded = value.encode("utf-8")
        else:
            padding = "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("invalid metadata encoding") from exc
    if len(decoded) > config.max_metadata_bytes:
        raise ValueError("metadata too large")
    try:
        data = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid metadata json") from exc
    if not isinstance(data, dict) or any(key not in METADATA_KEYS for key in data):
        raise ValueError("invalid metadata fields")
    return data


def sanitize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    if any(str(key) not in METADATA_KEYS for key in metadata):
        raise ValueError("invalid metadata fields")

    aliases = {
        "focus_events": "focus_count",
        "input_events": "input_count",
        "honeypot": "honeypot_filled",
    }
    canonical = {aliases.get(str(key), str(key)): value for key, value in metadata.items()}
    result: dict[str, Any] = {}
    for key in (
        "focus_count",
        "input_count",
        "pointer_count",
        "keyboard_count",
        "visibility_changes",
    ):
        if key in canonical:
            value = canonical[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("invalid metadata value")
            result[key] = min(1000, max(0, int(value)))
    if "form_fill_ms" in canonical:
        value = canonical["form_fill_ms"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid metadata value")
        result["form_fill_ms"] = min(3_600_000, max(0, int(value)))
    for key in ("page_visible", "honeypot_filled", "was_autofilled"):
        if key in canonical:
            if not isinstance(canonical[key], bool):
                raise ValueError("invalid metadata value")
            result[key] = canonical[key]
    return result


def safe_metadata_for_audit(metadata: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "form_fill_ms" in metadata:
        elapsed = int(metadata["form_fill_ms"])
        result["form_fill_bucket"] = (
            "under_1s"
            if elapsed < 1000
            else "1_to_3s"
            if elapsed < 3000
            else "3_to_10s"
            if elapsed < 10000
            else "over_10s"
        )
    for key in (
        "focus_count",
        "input_count",
        "pointer_count",
        "keyboard_count",
        "visibility_changes",
    ):
        if key in metadata:
            value = int(metadata[key])
            result[f"{key}_bucket"] = "zero" if value == 0 else "one" if value == 1 else "many"
    for key in ("page_visible", "honeypot_filled", "was_autofilled"):
        if key in metadata:
            result[key] = bool(metadata[key])
    return result
