from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core import checks
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import RequestFactory, override_settings
from django.utils import timezone

from triadcaptcha_django.admin import BlockRuleAdminForm, _admin_value_hash
from triadcaptcha_django.conf import ConfigurationPending, get_settings, get_settings_state
from triadcaptcha_django.models import (
    BlockRule,
    ProtectedAction,
    ProtectionConfiguration,
    SecurityEvent,
    SiteKeyVersion,
)
from triadcaptcha_django.signals import hash_identity
from triadcaptcha_django.site_keys import current_site_key, site_key_is_accepted

pytestmark = pytest.mark.django_db


def test_models_are_registered_in_standard_django_admin():
    for model in (
        ProtectionConfiguration,
        ProtectedAction,
        BlockRule,
        SecurityEvent,
        SiteKeyVersion,
    ):
        assert model in admin.site._registry


def test_admin_requires_standard_staff_authentication(client):
    response = client.get("/admin/triadcaptcha_django/securityevent/")
    assert response.status_code == 302
    user = get_user_model().objects.create_superuser("admin", "admin@example.test", "secret")
    client.force_login(user)
    assert client.get("/admin/triadcaptcha_django/securityevent/").status_code == 200


def test_view_only_admin_cannot_rotate_keys_or_unblock(client, policy):
    user = get_user_model().objects.create_user("auditor", password="secret", is_staff=True)
    permissions = Permission.objects.filter(
        content_type__app_label="triadcaptcha_django",
        codename__in=("view_sitekeyversion", "view_blockrule"),
    )
    user.user_permissions.add(*permissions)
    request = RequestFactory().get("/admin/")
    request.user = user
    assert "rotate_site_key" not in admin.site._registry[SiteKeyVersion].get_actions(request)
    assert "unblock_rules" not in admin.site._registry[BlockRule].get_actions(request)

    rule = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash="d" * 64,
        active=True,
    )
    key_count = SiteKeyVersion.objects.count()
    client.force_login(user)
    client.post(
        "/admin/triadcaptcha_django/sitekeyversion/",
        {"action": "rotate_site_key", "_selected_action": policy.pk},
    )
    client.post(
        "/admin/triadcaptcha_django/blockrule/",
        {"action": "unblock_rules", "_selected_action": rule.pk},
    )
    rule.refresh_from_db()
    assert SiteKeyVersion.objects.count() == key_count
    assert rule.active


def test_development_mode_cannot_validate_when_debug_false():
    config = ProtectionConfiguration(development_mode=True)
    with pytest.raises(ValidationError):
        config.full_clean()


def test_admin_phone_prefix_matches_runtime_identity_hash():
    assert _admin_value_hash(BlockRule.Scope.IDENTITY, "phone:+1 202-555-0100") == hash_identity(
        {"type": "phone", "value": "+1 202-555-0100"}
    )


def test_active_block_enforcement_fields_are_immutable_and_delete_is_disabled(policy):
    rule = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash="e" * 64,
        active=True,
    )
    model_admin = admin.site._registry[BlockRule]
    request = RequestFactory().get("/admin/triadcaptcha_django/blockrule/")
    readonly = model_admin.get_readonly_fields(request, rule)
    assert {"action", "scope", "active", "expires_at"}.issubset(readonly)
    assert not model_admin.has_delete_permission(request, rule)
    assert "raw_value" not in BlockRuleAdminForm(instance=rule).fields


@override_settings(TRIADCAPTCHA_HMAC_SECRET="short")
def test_system_check_rejects_short_secret():
    errors = checks.run_checks(tags=[checks.Tags.security])
    assert "triadcaptcha.E001" in {error.id for error in errors}


@override_settings(TRIADCAPTCHA_HMAC_SECRET="CHANGE_ME_32_bytes_or_more_random_server_secret")
def test_system_check_rejects_placeholder_secret():
    errors = checks.run_checks(tags=[checks.Tags.security])
    assert "triadcaptcha.E001" in {error.id for error in errors}


@override_settings(TRIADCAPTCHA_SITE_KEY="x" * 97)
def test_system_check_rejects_site_key_that_cannot_fit_model():
    errors = checks.run_checks(tags=[checks.Tags.security])
    assert "triadcaptcha.E004" in {error.id for error in errors}


def test_runtime_settings_resolver_accepts_mapping(settings):
    settings.TRIADCAPTCHA_SETTINGS_RESOLVER = lambda: {
        "site_key": "tc_site_runtime_resolver_123456",
        "hmac_secret": "runtime-challenge-secret-0123456789-abcdef",
    }
    resolved = get_settings()
    assert resolved.site_key == "tc_site_runtime_resolver_123456"
    assert resolved.hmac_secret == "runtime-challenge-secret-0123456789-abcdef"
    assert resolved.identifier_hmac_secret == settings.TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET


def test_pending_runtime_settings_fail_closed_without_blocking_checks(settings):
    def pending():
        raise ConfigurationPending("database row not initialized")

    settings.TRIADCAPTCHA_SETTINGS_RESOLVER = pending
    state = get_settings_state()
    assert state.pending
    assert state.settings.hmac_secret == ""
    messages = checks.run_checks(tags=[checks.Tags.security])
    assert {message.id for message in messages} == {"triadcaptcha.W002"}


def test_bootstrap_is_idempotent_and_does_not_undo_rotation(settings):
    stdout = StringIO()
    call_command("bootstrap_triadcaptcha", "--actions", "register", "login", stdout=stdout)
    call_command("bootstrap_triadcaptcha", "--actions", "register", "login", stdout=stdout)
    assert ProtectionConfiguration.objects.count() == 1
    assert ProtectedAction.objects.count() == 2
    env_key = SiteKeyVersion.objects.get(site_key=settings.TRIADCAPTCHA_SITE_KEY)
    assert env_key.status == SiteKeyVersion.Status.ACTIVE

    rotated = SiteKeyVersion.rotate(grace_period=timedelta(days=7))
    env_key.refresh_from_db()
    assert env_key.status == SiteKeyVersion.Status.GRACE
    call_command("bootstrap_triadcaptcha", "--actions", "register", "login", stdout=stdout)
    env_key.refresh_from_db()
    rotated.refresh_from_db()
    assert env_key.status == SiteKeyVersion.Status.GRACE
    assert rotated.status == SiteKeyVersion.Status.ACTIVE


def test_revoked_database_key_does_not_fall_back_to_environment(settings):
    SiteKeyVersion.objects.create(
        site_key=settings.TRIADCAPTCHA_SITE_KEY, status=SiteKeyVersion.Status.REVOKED
    )
    assert current_site_key() == ""
    assert not site_key_is_accepted(settings.TRIADCAPTCHA_SITE_KEY)


def test_cleanup_respects_retention(policy):
    event = SecurityEvent.objects.create(action="register", decision="allow")
    SecurityEvent.objects.filter(pk=event.pk).update(
        created_at=timezone.now() - timedelta(days=100)
    )
    call_command("cleanup_triadcaptcha", "--days", "90")
    assert not SecurityEvent.objects.filter(pk=event.pk).exists()


def test_cleanup_removes_only_stale_inactive_block_rules(policy):
    stale = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash="a" * 64,
        active=False,
        unblocked_at=timezone.now() - timedelta(days=100),
    )
    current = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash="b" * 64,
        active=False,
        unblocked_at=timezone.now() - timedelta(days=10),
    )
    permanent = BlockRule.objects.create(
        action=policy,
        scope=BlockRule.Scope.IDENTITY,
        value_hash="c" * 64,
        active=True,
    )

    call_command("cleanup_triadcaptcha", "--days", "90")

    assert not BlockRule.objects.filter(pk=stale.pk).exists()
    assert BlockRule.objects.filter(pk=current.pk).exists()
    assert BlockRule.objects.filter(pk=permanent.pk, active=True).exists()
