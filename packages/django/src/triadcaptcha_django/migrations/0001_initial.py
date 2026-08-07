# Generated for TriadCAPTCHA 0.1.0. Kept explicit so Git installs are immediately migratable.
import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models

import triadcaptcha_django.models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ProtectedAction",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        max_length=64,
                        unique=True,
                        validators=[triadcaptcha_django.models.action_validator],
                    ),
                ),
                ("description", models.CharField(blank=True, max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "fail_closed",
                    models.BooleanField(
                        default=True,
                        help_text=(
                            "Return 503 if Redis is unavailable. Recommended for sensitive actions."
                        ),
                    ),
                ),
                (
                    "base_risk_score",
                    models.PositiveSmallIntegerField(
                        default=0, validators=[django.core.validators.MaxValueValidator(100)]
                    ),
                ),
                (
                    "challenge_threshold",
                    models.PositiveSmallIntegerField(
                        default=40,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(99),
                        ],
                    ),
                ),
                (
                    "block_threshold",
                    models.PositiveSmallIntegerField(
                        default=80,
                        validators=[
                            django.core.validators.MinValueValidator(2),
                            django.core.validators.MaxValueValidator(100),
                        ],
                    ),
                ),
                (
                    "rate_window_seconds",
                    models.PositiveIntegerField(
                        default=60,
                        validators=[
                            django.core.validators.MinValueValidator(10),
                            django.core.validators.MaxValueValidator(86400),
                        ],
                    ),
                ),
                (
                    "ip_limit",
                    models.PositiveIntegerField(
                        default=30, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "identity_limit",
                    models.PositiveIntegerField(
                        default=12, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "session_limit",
                    models.PositiveIntegerField(
                        default=20, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "ip_identity_limit",
                    models.PositiveIntegerField(
                        default=8, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "identities_per_ip_limit",
                    models.PositiveIntegerField(
                        default=8, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "ips_per_identity_limit",
                    models.PositiveIntegerField(
                        default=5, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "failure_limit",
                    models.PositiveIntegerField(
                        default=5, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "challenge_ttl_seconds",
                    models.PositiveIntegerField(
                        default=120,
                        validators=[
                            django.core.validators.MinValueValidator(15),
                            django.core.validators.MaxValueValidator(900),
                        ],
                    ),
                ),
                (
                    "challenge_issue_limit",
                    models.PositiveIntegerField(
                        default=10, validators=[django.core.validators.MinValueValidator(1)]
                    ),
                ),
                (
                    "temporary_block_seconds",
                    models.PositiveIntegerField(
                        default=900,
                        validators=[
                            django.core.validators.MinValueValidator(30),
                            django.core.validators.MaxValueValidator(604800),
                        ],
                    ),
                ),
                (
                    "pow_algorithm",
                    models.CharField(
                        choices=[
                            ("PBKDF2/SHA-256", "PBKDF2 / SHA-256"),
                            ("PBKDF2/SHA-384", "PBKDF2 / SHA-384"),
                            ("PBKDF2/SHA-512", "PBKDF2 / SHA-512"),
                            ("SHA-256", "Iterated SHA-256"),
                        ],
                        default="PBKDF2/SHA-256",
                        max_length=32,
                    ),
                ),
                (
                    "pow_cost",
                    models.PositiveIntegerField(
                        default=5000,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(1000000),
                        ],
                    ),
                ),
                (
                    "pow_min_counter",
                    models.PositiveIntegerField(
                        default=5000,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(1000000),
                        ],
                    ),
                ),
                (
                    "pow_max_counter",
                    models.PositiveIntegerField(
                        default=10000,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(2000000),
                        ],
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "protected action",
                "verbose_name_plural": "protected actions",
                "ordering": ("action",),
            },
        ),
        migrations.CreateModel(
            name="ProtectionConfiguration",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1, editable=False, primary_key=True, serialize=False
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                (
                    "development_mode",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "Only effective when Django DEBUG and "
                            "TRIADCAPTCHA_DEVELOPMENT_MODE are both true."
                        ),
                    ),
                ),
                (
                    "audit_retention_days",
                    models.PositiveIntegerField(
                        default=90,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(3650),
                        ],
                    ),
                ),
                (
                    "allow_audit_sample_rate",
                    models.FloatField(
                        default=0.05,
                        validators=[
                            django.core.validators.MinValueValidator(0.0),
                            django.core.validators.MaxValueValidator(1.0),
                        ],
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "protection configuration",
                "verbose_name_plural": "protection configuration",
            },
        ),
        migrations.CreateModel(
            name="SiteKeyVersion",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("site_key", models.CharField(editable=False, max_length=96, unique=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("grace", "Grace period"),
                            ("revoked", "Revoked"),
                        ],
                        default="active",
                        max_length=12,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("not_before", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("note", models.CharField(blank=True, max_length=200)),
            ],
            options={
                "verbose_name": "site key version",
                "verbose_name_plural": "site key versions",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="SecurityEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "action",
                    models.CharField(
                        db_index=True,
                        max_length=64,
                        validators=[triadcaptcha_django.models.action_validator],
                    ),
                ),
                (
                    "decision",
                    models.CharField(
                        choices=[
                            ("allow", "Allow"),
                            ("challenge_required", "Challenge required"),
                            ("block", "Block"),
                            ("challenge_issued", "Challenge issued"),
                            ("outcome", "Business outcome"),
                        ],
                        max_length=24,
                    ),
                ),
                ("public_code", models.CharField(blank=True, max_length=64)),
                ("risk_score", models.PositiveSmallIntegerField(default=0)),
                ("reason_codes", models.JSONField(blank=True, default=list)),
                ("ip_hash", models.CharField(blank=True, max_length=64)),
                ("identity_hash", models.CharField(blank=True, max_length=64)),
                ("session_hash", models.CharField(blank=True, max_length=64)),
                ("ip_identity_hash", models.CharField(blank=True, max_length=64)),
                ("user_agent_family", models.CharField(blank=True, max_length=32)),
                ("safe_metadata", models.JSONField(blank=True, default=dict)),
            ],
            options={
                "verbose_name": "security event",
                "verbose_name_plural": "security events",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="BlockRule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "scope",
                    models.CharField(
                        choices=[
                            ("ip", "IP HMAC"),
                            ("identity", "Identity HMAC"),
                            ("session", "Session HMAC"),
                            ("ip_identity", "IP + identity HMAC"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "value_hash",
                    models.CharField(
                        max_length=64, validators=[triadcaptcha_django.models.hash_validator]
                    ),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[("manual", "Manual"), ("automatic", "Automatic")],
                        default="manual",
                        max_length=12,
                    ),
                ),
                ("reason_code", models.CharField(default="manual_block", max_length=64)),
                ("internal_reason", models.TextField(blank=True)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("unblocked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "action",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="block_rules",
                        to="triadcaptcha_django.protectedaction",
                    ),
                ),
            ],
            options={
                "verbose_name": "block rule",
                "verbose_name_plural": "block rules",
                "ordering": ("-created_at",),
            },
        ),
        migrations.AddIndex(
            model_name="securityevent",
            index=models.Index(fields=["action", "created_at"], name="tc_event_act_time_ix"),
        ),
        migrations.AddIndex(
            model_name="securityevent",
            index=models.Index(
                fields=["identity_hash", "created_at"], name="tc_event_ident_time_ix"
            ),
        ),
        migrations.AddIndex(
            model_name="securityevent",
            index=models.Index(fields=["ip_hash", "created_at"], name="tc_event_ip_time_ix"),
        ),
        migrations.AddIndex(
            model_name="blockrule",
            index=models.Index(fields=["scope", "value_hash", "active"], name="tc_block_lookup_ix"),
        ),
        migrations.AddIndex(
            model_name="blockrule",
            index=models.Index(fields=["expires_at"], name="tc_block_expiry_ix"),
        ),
    ]
