from __future__ import annotations

import ipaddress
import re

from django import forms
from django.contrib import admin, messages
from django.db.models import QuerySet
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_post_parameters
from redis.exceptions import RedisError

from . import __version__
from .conf import get_settings, secret_is_acceptable
from .models import (
    BlockRule,
    ProtectedAction,
    ProtectionConfiguration,
    SecurityEvent,
    SiteKeyVersion,
)
from .redis_backend import (
    RedisUnavailable,
    clear_temporary_block,
    get_redis_client,
    set_temporary_block,
)
from .signals import _hmac_hex, hash_identity, hash_pair
from .site_keys import current_site_key


class SuperuserManagedAdmin(admin.ModelAdmin):
    """Keep security-policy mutations behind the strongest built-in role."""

    def has_module_permission(self, request) -> bool:
        return bool(request.user and request.user.is_superuser)

    def has_view_permission(self, request, obj=None) -> bool:
        return bool(request.user and request.user.is_superuser)

    def has_add_permission(self, request) -> bool:
        return bool(request.user and request.user.is_superuser)

    def has_change_permission(self, request, obj=None) -> bool:
        return bool(request.user and request.user.is_superuser)

    def has_delete_permission(self, request, obj=None) -> bool:
        return bool(request.user and request.user.is_superuser)


class ProtectionConfigurationForm(forms.ModelForm):
    class Meta:
        model = ProtectionConfiguration
        fields = "__all__"

    def clean_development_mode(self):
        value = self.cleaned_data["development_mode"]
        if value and not self.request_debug:
            raise forms.ValidationError(_("Development mode requires Django DEBUG."))
        return value

    @property
    def request_debug(self) -> bool:
        from django.conf import settings

        return settings.DEBUG


@admin.register(ProtectionConfiguration)
class ProtectionConfigurationAdmin(SuperuserManagedAdmin):
    form = ProtectionConfigurationForm
    list_display = ("enabled", "development_mode", "audit_retention_days", "updated_at")
    readonly_fields = (
        "package_version",
        "redis_status",
        "challenge_secret_status",
        "identifier_secret_status",
        "active_site_key_status",
        "trusted_proxy_status",
        "created_at",
        "updated_at",
    )
    fieldsets = (
        (
            "Состояние интеграции",
            {
                "fields": (
                    "package_version",
                    "redis_status",
                    "challenge_secret_status",
                    "identifier_secret_status",
                    "active_site_key_status",
                    "trusted_proxy_status",
                ),
                "description": "Секреты никогда не отображаются и не сохраняются в базе данных.",
            },
        ),
        (
            "Основная защита",
            {
                "fields": ("enabled", "development_mode"),
                "description": "Development mode допустим только при DEBUG=True.",
            },
        ),
        (
            "Аудит и хранение",
            {"fields": ("audit_retention_days", "allow_audit_sample_rate")},
        ),
        ("Служебные поля", {"fields": ("created_at", "updated_at")}),
    )

    def has_add_permission(self, request) -> bool:
        return super().has_add_permission(request) and not ProtectionConfiguration.objects.exists()

    def has_delete_permission(self, request, obj=None) -> bool:
        return False

    @admin.display(description="Версия пакета")
    def package_version(self, _obj) -> str:
        return __version__

    @admin.display(description="Redis")
    def redis_status(self, _obj) -> str:
        try:
            return "Доступен" if get_redis_client().ping() else "Не отвечает"
        except (RedisError, OSError, ValueError):
            return "Недоступен"

    @admin.display(description="HMAC challenge secret")
    def challenge_secret_status(self, _obj) -> str:
        return "Настроен" if secret_is_acceptable(get_settings().hmac_secret) else "Не настроен"

    @admin.display(description="HMAC identifier secret")
    def identifier_secret_status(self, _obj) -> str:
        configured = secret_is_acceptable(get_settings().identifier_hmac_secret)
        return "Настроен" if configured else "Не настроен"

    @admin.display(description="Активный публичный site key")
    def active_site_key_status(self, _obj) -> str:
        key = current_site_key()
        return f"{key[:18]}…" if key else "Не настроен"

    @admin.display(description="Доверенные proxy-сети")
    def trusted_proxy_status(self, _obj) -> str:
        networks = get_settings().trusted_proxy_networks
        return ", ".join(networks) if networks else "Не настроены"


@admin.register(ProtectedAction)
class ProtectedActionAdmin(SuperuserManagedAdmin):
    list_display = (
        "action",
        "enabled",
        "fail_closed",
        "challenge_threshold",
        "block_threshold",
        "pow_algorithm",
    )
    list_filter = ("enabled", "fail_closed", "pow_algorithm")
    search_fields = ("action", "description")
    fieldsets = (
        (None, {"fields": ("action", "description", "enabled", "fail_closed")}),
        (
            "Пороговые значения риска",
            {"fields": ("base_risk_score", "challenge_threshold", "block_threshold")},
        ),
        (
            "Лимиты частоты и разнообразия",
            {
                "fields": (
                    "rate_window_seconds",
                    "ip_limit",
                    "identity_limit",
                    "session_limit",
                    "ip_identity_limit",
                    "identities_per_ip_limit",
                    "ips_per_identity_limit",
                    "failure_limit",
                )
            },
        ),
        (
            "Proof-of-Work",
            {
                "fields": (
                    "challenge_ttl_seconds",
                    "challenge_issue_limit",
                    "proof_retry_limit",
                    "temporary_block_seconds",
                    "pow_algorithm",
                    "pow_cost",
                    "pow_min_counter",
                    "pow_max_counter",
                )
            },
        ),
    )


@admin.action(
    description=_("Rotate selected installation's public site key"),
    permissions=("change",),
)
def rotate_site_key(modeladmin, request, queryset: QuerySet):
    SiteKeyVersion.rotate(note=f"Rotated by admin user {request.user.pk}")
    modeladmin.message_user(
        request,
        _("A new public site key was created; the previous key has a seven-day grace period."),
        messages.SUCCESS,
    )


@admin.register(SiteKeyVersion)
class SiteKeyVersionAdmin(SuperuserManagedAdmin):
    list_display = ("site_key", "status", "created_at", "not_before", "expires_at")
    list_filter = ("status",)
    readonly_fields = ("site_key", "status", "created_at", "not_before", "expires_at", "note")
    actions = (rotate_site_key,)

    def has_add_permission(self, request) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


def _admin_value_hash(scope: str, raw_value: str) -> str:
    def identity_hash(value: str) -> str:
        kind, separator, identity_value = value.partition(":")
        if separator and kind.casefold() in {"email", "phone", "generic"}:
            return hash_identity((kind.casefold(), identity_value))
        return hash_identity(value)

    value = raw_value.strip()
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    if scope == BlockRule.Scope.IP:
        normalized = ipaddress.ip_address(value).compressed
        return _hmac_hex("ip", normalized)
    if scope == BlockRule.Scope.IDENTITY:
        return identity_hash(value)
    if scope == BlockRule.Scope.IP_IDENTITY:
        raw_ip, separator, identity = value.partition("|")
        if not separator:
            raise ValueError("Use IP|identity for a combined rule.")
        ip_hash = _hmac_hex("ip", ipaddress.ip_address(raw_ip.strip()).compressed)
        return hash_pair(ip_hash, identity_hash(identity.strip()))
    return _hmac_hex("session", f"django:{value}")


class BlockRuleAdminForm(forms.ModelForm):
    raw_value = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=_(
            "On add, enter a raw IP, email:value or phone:value identity, an "
            "IP|type:value pair, session key, or existing 64-character HMAC. "
            "The raw value is never stored."
        ),
    )

    class Meta:
        model = BlockRule
        exclude = ("value_hash", "unblocked_at")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            # A replacement target would need to clear the old Redis key and is
            # therefore intentionally modelled as unblock + create, not edit.
            self.fields.pop("raw_value", None)

    def clean(self):
        cleaned = super().clean()
        raw = cleaned.get("raw_value")
        if self.instance._state.adding and not raw:
            self.add_error("raw_value", _("A value is required for a new rule."))
        if raw and cleaned.get("scope"):
            try:
                self.instance.value_hash = _admin_value_hash(cleaned["scope"], raw)
            except ValueError as exc:
                self.add_error("raw_value", str(exc))
        return cleaned


@admin.action(description=_("Unblock selected rules"), permissions=("change",))
def unblock_rules(modeladmin, request, queryset: QuerySet):
    count = 0
    redis_failed = False
    for rule in queryset.filter(active=True):
        rule.unblock()
        count += 1
        try:
            clear_temporary_block(
                rule.scope,
                rule.value_hash,
                rule.action.action if rule.action_id else None,
            )
        except RedisUnavailable:
            redis_failed = True
    level = messages.WARNING if redis_failed else messages.SUCCESS
    suffix = _(" Redis cleanup failed; the TTL will still expire.") if redis_failed else ""
    modeladmin.message_user(
        request, _("Unblocked %(count)s rule(s).") % {"count": count} + suffix, level
    )


@admin.register(BlockRule)
class BlockRuleAdmin(SuperuserManagedAdmin):
    form = BlockRuleAdminForm
    list_display = ("scope", "short_hash", "action", "source", "active", "expires_at")
    list_filter = ("scope", "source", "active", "action")
    search_fields = ("value_hash", "reason_code")
    readonly_fields = ("value_hash", "source", "created_at", "unblocked_at")
    actions = (unblock_rules,)

    def get_readonly_fields(self, request, obj=None):
        fields = tuple(super().get_readonly_fields(request, obj))
        if obj is not None:
            # Enforcement coordinates are immutable after creation. Disabling an
            # active rule must go through the action that also clears Redis.
            fields += ("action", "scope", "active", "expires_at")
        return fields

    def has_delete_permission(self, request, obj=None) -> bool:
        # Deleting or directly disabling a row would leave its Redis block alive.
        # Use the unblock action; retention cleanup later removes inactive rows.
        return False

    @method_decorator(sensitive_post_parameters("raw_value"))
    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)

    @admin.display(description=_("Value HMAC"))
    def short_hash(self, obj) -> str:
        return obj.value_hash[:16] + "…"

    def save_model(self, request, obj, form, change) -> None:
        if not change:
            obj.source = BlockRule.Source.MANUAL
        super().save_model(request, obj, form, change)
        if obj.active and obj.action_id and obj.expires_at:
            ttl = max(1, int((obj.expires_at - timezone.now()).total_seconds()))
            try:
                set_temporary_block(obj.scope, obj.value_hash, obj.action.action, ttl)
            except RedisUnavailable:
                self.message_user(
                    request,
                    _("Rule was saved in PostgreSQL, but Redis was unavailable."),
                    messages.WARNING,
                )


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "decision", "public_code", "risk_score")
    list_filter = ("decision", "action", "created_at")
    search_fields = ("ip_hash", "identity_hash", "session_hash", "ip_identity_hash")
    date_hierarchy = "created_at"
    readonly_fields = tuple(field.name for field in SecurityEvent._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return request.user.has_perm("triadcaptcha_django.view_securityevent")

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
