from __future__ import annotations

import django
from django.core.management.base import BaseCommand, CommandError

from ...models import ProtectedAction
from ...signals import validate_action

MIN_PRODUCTION_DJANGO = (5, 2)


class Command(BaseCommand):
    help = "Fail unless TriadCAPTCHA's production security prerequisites are satisfied."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--allow-fail-open",
            action="append",
            default=[],
            metavar="ACTION",
            help="Explicitly approve one enabled low-impact fail-open action.",
        )

    def handle(self, *args, **options) -> None:
        if django.VERSION[:2] < MIN_PRODUCTION_DJANGO:
            raise CommandError("Production requires supported Django 5.2 or newer.")

        try:
            approved = {validate_action(value) for value in options["allow_fail_open"]}
        except ValueError as exc:
            raise CommandError("Every --allow-fail-open value must be a valid action.") from exc

        configured = set(
            ProtectedAction.objects.filter(enabled=True, fail_closed=False).values_list(
                "action", flat=True
            )
        )
        unknown = approved - configured
        if unknown:
            raise CommandError(
                "Fail-open approval does not match an enabled fail-open policy: "
                + ", ".join(sorted(unknown))
            )
        unapproved = configured - approved
        if unapproved:
            raise CommandError(
                "Enabled fail-open policies require explicit approval: "
                + ", ".join(sorted(unapproved))
            )

        self.stdout.write(self.style.SUCCESS("TriadCAPTCHA production preflight passed."))
