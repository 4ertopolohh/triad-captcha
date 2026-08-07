from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from ...conf import get_settings, site_key_is_configured
from ...models import ProtectedAction, ProtectionConfiguration, SiteKeyVersion
from ...signals import validate_action


class Command(BaseCommand):
    help = "Idempotently create TriadCAPTCHA configuration, site key, and action policies."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--actions",
            nargs="*",
            default=("register", "login", "lead"),
            help="Action slugs to create (default: register login lead).",
        )

    @transaction.atomic
    def handle(self, *args, **options) -> None:
        config = get_settings()
        if not site_key_is_configured(config.site_key):
            raise CommandError("TRIADCAPTCHA_SITE_KEY is invalid.")
        try:
            actions = tuple(validate_action(action) for action in options["actions"])
        except ValueError as exc:
            raise CommandError("Every action must be a valid TriadCAPTCHA action slug.") from exc
        ProtectionConfiguration.objects.get_or_create(pk=1)

        has_any_key = SiteKeyVersion.objects.exists()
        key_version, created = SiteKeyVersion.objects.get_or_create(
            site_key=config.site_key,
            defaults={
                "status": (
                    SiteKeyVersion.Status.GRACE if has_any_key else SiteKeyVersion.Status.ACTIVE
                ),
                "expires_at": timezone.now() + timedelta(days=7) if has_any_key else None,
                "note": "Environment bootstrap",
            },
        )
        # Existing states are deliberately preserved: a restart must not undo an
        # administrator's rotation or revocation.

        created_actions = []
        for action in actions:
            policy, was_created = ProtectedAction.objects.get_or_create(action=action)
            if was_created:
                created_actions.append(policy.action)
        self.stdout.write(
            self.style.SUCCESS(
                f"TriadCAPTCHA bootstrapped; site key "
                f"{'created' if created else 'present'}, actions: {', '.join(actions)}"
            )
        )
        if created_actions:
            self.stdout.write("Created policies: " + ", ".join(created_actions))
