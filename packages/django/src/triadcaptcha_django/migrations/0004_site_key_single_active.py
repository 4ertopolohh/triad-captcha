from datetime import timedelta

from django.db import migrations, models
from django.utils import timezone


def reconcile_active_site_keys(apps, schema_editor):
    site_key_version = apps.get_model("triadcaptcha_django", "SiteKeyVersion")
    active = list(
        site_key_version.objects.filter(status="active").order_by("-created_at", "-pk")
    )
    if len(active) < 2:
        return
    latest_acceptable_expiry = timezone.now() + timedelta(days=7)
    for duplicate in active[1:]:
        duplicate.status = "grace"
        if duplicate.expires_at is None or duplicate.expires_at > latest_acceptable_expiry:
            duplicate.expires_at = latest_acceptable_expiry
        duplicate.save(update_fields=("status", "expires_at"))


class Migration(migrations.Migration):
    dependencies = [("triadcaptcha_django", "0003_protectedaction_proof_retry_limit")]

    operations = [
        migrations.RunPython(reconcile_active_site_keys, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="sitekeyversion",
            constraint=models.UniqueConstraint(
                fields=("status",),
                condition=models.Q(status="active"),
                name="tc_one_active_site_key",
            ),
        ),
    ]
