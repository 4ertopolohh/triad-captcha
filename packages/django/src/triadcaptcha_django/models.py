from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

action_validator = RegexValidator(
    regex=r"^[a-z][a-z0-9_.:-]{0,63}$",
    message=_("Use 1–64 lower-case letters, digits, dots, colons, underscores, or hyphens."),
)
hash_validator = RegexValidator(regex=r"^[0-9a-f]{64}$", message=_("Expected a SHA-256 HMAC."))


class ProtectionConfiguration(models.Model):
    """Installation-wide operational configuration (a singleton row)."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    enabled = models.BooleanField(default=True)
    development_mode = models.BooleanField(
        default=False,
        help_text=_(
            "Only effective when Django DEBUG and TRIADCAPTCHA_DEVELOPMENT_MODE are both true."
        ),
    )
    audit_retention_days = models.PositiveIntegerField(
        default=90, validators=[MinValueValidator(1), MaxValueValidator(3650)]
    )
    allow_audit_sample_rate = models.FloatField(
        default=0.05, validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("protection configuration")
        verbose_name_plural = _("protection configuration")

    def clean(self) -> None:
        super().clean()
        if self.development_mode and not settings.DEBUG:
            raise ValidationError(
                {"development_mode": _("Development mode cannot be enabled when DEBUG is false.")}
            )

    def save(self, *args, **kwargs) -> None:
        self.pk = 1
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return str(_("TriadCAPTCHA configuration"))


class ProtectedAction(models.Model):
    """Policy for one business action such as ``register`` or ``send_code``."""

    class PowAlgorithm(models.TextChoices):
        PBKDF2_SHA256 = "PBKDF2/SHA-256", "PBKDF2 / SHA-256"
        PBKDF2_SHA384 = "PBKDF2/SHA-384", "PBKDF2 / SHA-384"
        PBKDF2_SHA512 = "PBKDF2/SHA-512", "PBKDF2 / SHA-512"
        SHA256 = "SHA-256", "Iterated SHA-256"

    action = models.CharField(max_length=64, unique=True, validators=[action_validator])
    description = models.CharField(max_length=200, blank=True)
    enabled = models.BooleanField(default=True)
    fail_closed = models.BooleanField(
        default=True,
        help_text=_("Return 503 if Redis is unavailable. Recommended for sensitive actions."),
    )

    base_risk_score = models.PositiveSmallIntegerField(
        default=0, validators=[MaxValueValidator(100)]
    )
    challenge_threshold = models.PositiveSmallIntegerField(
        default=40, validators=[MinValueValidator(1), MaxValueValidator(99)]
    )
    block_threshold = models.PositiveSmallIntegerField(
        default=80, validators=[MinValueValidator(2), MaxValueValidator(100)]
    )

    rate_window_seconds = models.PositiveIntegerField(
        default=60, validators=[MinValueValidator(10), MaxValueValidator(86400)]
    )
    ip_limit = models.PositiveIntegerField(default=30, validators=[MinValueValidator(1)])
    identity_limit = models.PositiveIntegerField(default=12, validators=[MinValueValidator(1)])
    session_limit = models.PositiveIntegerField(default=20, validators=[MinValueValidator(1)])
    ip_identity_limit = models.PositiveIntegerField(default=8, validators=[MinValueValidator(1)])
    identities_per_ip_limit = models.PositiveIntegerField(
        default=8, validators=[MinValueValidator(1)]
    )
    ips_per_identity_limit = models.PositiveIntegerField(
        default=5, validators=[MinValueValidator(1)]
    )
    failure_limit = models.PositiveIntegerField(default=5, validators=[MinValueValidator(1)])

    challenge_ttl_seconds = models.PositiveIntegerField(
        default=120, validators=[MinValueValidator(15), MaxValueValidator(900)]
    )
    challenge_issue_limit = models.PositiveIntegerField(
        default=10, validators=[MinValueValidator(1)]
    )
    temporary_block_seconds = models.PositiveIntegerField(
        default=900, validators=[MinValueValidator(30), MaxValueValidator(604800)]
    )

    pow_algorithm = models.CharField(
        max_length=32, choices=PowAlgorithm.choices, default=PowAlgorithm.PBKDF2_SHA256
    )
    pow_cost = models.PositiveIntegerField(
        default=5000, validators=[MinValueValidator(1), MaxValueValidator(1_000_000)]
    )
    pow_min_counter = models.PositiveIntegerField(
        default=5000, validators=[MinValueValidator(1), MaxValueValidator(1_000_000)]
    )
    pow_max_counter = models.PositiveIntegerField(
        default=10000, validators=[MinValueValidator(1), MaxValueValidator(2_000_000)]
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("action",)
        verbose_name = _("protected action")
        verbose_name_plural = _("protected actions")

    def clean(self) -> None:
        super().clean()
        if self.challenge_threshold >= self.block_threshold:
            raise ValidationError(
                {"block_threshold": _("Block threshold must exceed challenge threshold.")}
            )
        if self.pow_max_counter < self.pow_min_counter:
            raise ValidationError(
                {"pow_max_counter": _("Maximum counter must not be below minimum counter.")}
            )

    def __str__(self) -> str:
        return self.action


class SiteKeyVersion(models.Model):
    """Versioned public installation identifiers; these are not security secrets."""

    class Status(models.TextChoices):
        ACTIVE = "active", _("Active")
        GRACE = "grace", _("Grace period")
        REVOKED = "revoked", _("Revoked")

    site_key = models.CharField(max_length=96, unique=True, editable=False)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    not_before = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(blank=True, null=True)
    note = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = _("site key version")
        verbose_name_plural = _("site key versions")

    @staticmethod
    def generate_key() -> str:
        return "tc_site_" + secrets.token_urlsafe(32)

    @classmethod
    def rotate(cls, *, grace_period: timedelta = timedelta(days=7), note: str = ""):
        now = timezone.now()
        with transaction.atomic():
            cls.objects.select_for_update().filter(status=cls.Status.ACTIVE).update(
                status=cls.Status.GRACE, expires_at=now + grace_period
            )
            return cls.objects.create(
                site_key=cls.generate_key(), status=cls.Status.ACTIVE, note=note
            )

    def save(self, *args, **kwargs) -> None:
        if not self.site_key:
            self.site_key = self.generate_key()
        super().save(*args, **kwargs)

    def is_accepted(self, at=None) -> bool:
        at = at or timezone.now()
        if self.not_before > at or self.status == self.Status.REVOKED:
            return False
        return self.expires_at is None or self.expires_at > at

    def __str__(self) -> str:
        # Public key, but a short form keeps admin lists readable.
        return f"{self.site_key[:18]}… ({self.status})"


class BlockRule(models.Model):
    class Scope(models.TextChoices):
        IP = "ip", _("IP HMAC")
        IDENTITY = "identity", _("Identity HMAC")
        SESSION = "session", _("Session HMAC")
        IP_IDENTITY = "ip_identity", _("IP + identity HMAC")

    class Source(models.TextChoices):
        MANUAL = "manual", _("Manual")
        AUTOMATIC = "automatic", _("Automatic")

    action = models.ForeignKey(
        ProtectedAction, blank=True, null=True, on_delete=models.CASCADE, related_name="block_rules"
    )
    scope = models.CharField(max_length=16, choices=Scope.choices)
    value_hash = models.CharField(max_length=64, validators=[hash_validator])
    source = models.CharField(max_length=12, choices=Source.choices, default=Source.MANUAL)
    reason_code = models.CharField(max_length=64, default="manual_block")
    internal_reason = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    unblocked_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("scope", "value_hash", "active"), name="tc_block_lookup_ix"),
            models.Index(fields=("expires_at",), name="tc_block_expiry_ix"),
        ]
        verbose_name = _("block rule")
        verbose_name_plural = _("block rules")

    def is_effective(self, at=None) -> bool:
        at = at or timezone.now()
        return self.active and (self.expires_at is None or self.expires_at > at)

    def unblock(self) -> None:
        self.active = False
        self.unblocked_at = timezone.now()
        self.save(update_fields=("active", "unblocked_at"))

    def __str__(self) -> str:
        target = self.value_hash[:12] + "…"
        return f"{self.scope}:{target}"


class SecurityEvent(models.Model):
    class Decision(models.TextChoices):
        ALLOW = "allow", _("Allow")
        CHALLENGE = "challenge_required", _("Challenge required")
        BLOCK = "block", _("Block")
        CHALLENGE_ISSUED = "challenge_issued", _("Challenge issued")
        OUTCOME = "outcome", _("Business outcome")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=64, validators=[action_validator], db_index=True)
    decision = models.CharField(max_length=24, choices=Decision.choices)
    public_code = models.CharField(max_length=64, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    reason_codes = models.JSONField(default=list, blank=True)
    ip_hash = models.CharField(max_length=64, blank=True)
    identity_hash = models.CharField(max_length=64, blank=True)
    session_hash = models.CharField(max_length=64, blank=True)
    ip_identity_hash = models.CharField(max_length=64, blank=True)
    user_agent_family = models.CharField(max_length=32, blank=True)
    safe_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("action", "created_at"), name="tc_event_act_time_ix"),
            models.Index(fields=("identity_hash", "created_at"), name="tc_event_ident_time_ix"),
            models.Index(fields=("ip_hash", "created_at"), name="tc_event_ip_time_ix"),
        ]
        verbose_name = _("security event")
        verbose_name_plural = _("security events")

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} {self.decision}"
