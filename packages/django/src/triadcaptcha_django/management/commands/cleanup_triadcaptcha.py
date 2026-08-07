from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ...models import BlockRule, ProtectionConfiguration, SecurityEvent


class Command(BaseCommand):
    help = "Delete TriadCAPTCHA audit events beyond the configured retention period."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--days", type=int, default=None)
        parser.add_argument("--dry-run", action="store_true")

    @transaction.atomic
    def handle(self, *args, **options) -> None:
        configured = (
            ProtectionConfiguration.objects.filter(pk=1)
            .values_list("audit_retention_days", flat=True)
            .first()
        )
        days = options["days"] if options["days"] is not None else configured or 90
        if days < 1:
            raise CommandError("Retention days must be positive.")
        cutoff = timezone.now() - timedelta(days=days)
        event_query = SecurityEvent.objects.filter(created_at__lt=cutoff)
        now = timezone.now()
        expired_rules = BlockRule.objects.filter(expires_at__lt=now, active=True)
        stale_inactive_rules = BlockRule.objects.filter(active=False).filter(
            Q(unblocked_at__lt=cutoff)
            | Q(unblocked_at__isnull=True, expires_at__lt=cutoff)
            | Q(unblocked_at__isnull=True, expires_at__isnull=True, created_at__lt=cutoff)
        )
        event_count = event_query.count()
        deactivated_count = expired_rules.count()
        deleted_rule_count = stale_inactive_rules.count()
        if not options["dry_run"]:
            event_query.delete()
            stale_inactive_rules.delete()
            expired_rules.update(active=False, unblocked_at=now)
        label = "Would clean" if options["dry_run"] else "Cleaned"
        self.stdout.write(
            f"{label} {event_count} event(s), delete {deleted_rule_count} inactive "
            f"rule(s), and deactivate {deactivated_count} expired active rule(s)."
        )
