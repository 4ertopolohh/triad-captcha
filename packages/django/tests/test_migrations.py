from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone


@pytest.mark.django_db(transaction=True)
def test_active_site_key_migration_keeps_newest_and_bounds_older_grace_expiry():
    before = ("triadcaptcha_django", "0003_protectedaction_proof_retry_limit")
    after = ("triadcaptcha_django", "0004_site_key_single_active")
    executor = MigrationExecutor(connection)
    executor.migrate([before])

    old_apps = executor.loader.project_state([before]).apps
    site_key_version = old_apps.get_model("triadcaptcha_django", "SiteKeyVersion")
    older = site_key_version.objects.create(site_key="tc_site_migration_older", status="active")
    newer = site_key_version.objects.create(site_key="tc_site_migration_newer", status="active")
    now = timezone.now()
    site_key_version.objects.filter(pk=older.pk).update(created_at=now - timedelta(days=2))
    site_key_version.objects.filter(pk=newer.pk).update(created_at=now - timedelta(days=1))

    executor = MigrationExecutor(connection)
    executor.migrate([after])
    new_apps = executor.loader.project_state([after]).apps
    migrated = new_apps.get_model("triadcaptcha_django", "SiteKeyVersion")
    older = migrated.objects.get(site_key="tc_site_migration_older")
    newer = migrated.objects.get(site_key="tc_site_migration_newer")

    assert newer.status == "active"
    assert newer.expires_at is None
    assert older.status == "grace"
    assert now < older.expires_at <= now + timedelta(days=7, seconds=5)
