# triadcaptcha-django

Reusable Django application for the self-hosted TriadCAPTCHA anti-bot system.

This package is intentionally not a hosted service. It uses the host project's PostgreSQL
database and a mandatory Redis instance. See the repository-level documentation for full
installation and integration instructions.

Supported compatibility range: Python 3.10–3.14 and Django 4.2–6.1. Django 5.2 LTS or 6.1 is the
recommended production baseline. Django 4.2 is retained as a legacy compatibility lane but no
longer receives upstream security fixes; applications should migrate to 5.2 LTS or newer.
