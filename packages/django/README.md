# triadcaptcha-django

Reusable Django application for the self-hosted TriadCAPTCHA anti-bot system.

This package is intentionally not a hosted service. It uses the host project's PostgreSQL
database and a mandatory Redis instance. See the repository-level documentation for full
installation and integration instructions.

## Runtime settings resolver

Database-backed installations may set `TRIADCAPTCHA_SETTINGS_RESOLVER` to a callable or
dotted callable path. The resolver must return `triadcaptcha_django.conf.TriadCaptchaSettings`
or a mapping with the same fields. It is evaluated at runtime so configuration changes do not
require a process restart.

While the database is unavailable or has not been initialized, a resolver may raise
`triadcaptcha_django.conf.ConfigurationPending`. Protection then fails closed and the Django
system check reports `triadcaptcha.W002` instead of blocking initial migrations.

Supported compatibility range: Python 3.10–3.14 and Django 4.2–6.1. Django 5.2 LTS or 6.1 is the
recommended production baseline. Django 4.2 is retained as a legacy compatibility lane but no
longer receives upstream security fixes; applications should migrate to 5.2 LTS or newer.

Version 0.2 introduces a short-lived logical-attempt handshake. A challenged 428
contains `error.attempt`; clients must send it as `X-TriadCAPTCHA-Attempt` on the
challenge request and proof retry. Deploy the 0.2 Django and React packages
together. Production startup should run `check_triadcaptcha_production` after
migrations; Redis pool size/queue timeout and fallback-cookie SameSite mode are
configurable through the documented `TRIADCAPTCHA_REDIS_*` and
`TRIADCAPTCHA_CONTEXT_COOKIE_*` settings.
