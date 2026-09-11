# Operations

## Bootstrap and checks

After installing the app and setting its environment variables:

```bash
python manage.py migrate
python manage.py bootstrap_triadcaptcha --actions register login send_code password_reset comments
python manage.py check --deploy
python manage.py check_triadcaptcha_production
```

The bootstrap command is idempotent. It creates the singleton configuration,
initial public site-key version, and only missing action policies; it does not
overwrite tuned policies. Review thresholds in Django admin before production.

Django system checks reject short/equal HMAC secrets, an invalid Redis scheme,
bad proxy networks, a missing public site key, and development mode combined with
`DEBUG=False`.

The production preflight requires Django 5.2 or newer and rejects every enabled
`fail_closed=False` action unless its name is explicitly repeated with
`--allow-fail-open`. An approval is an application risk decision, not a default.

## Audit retention

Set the retention period in **TriadCAPTCHA → Protection configuration**, then run
this daily from the host scheduler:

```bash
python manage.py cleanup_triadcaptcha --dry-run
python manage.py cleanup_triadcaptcha --batch-size 1000
```

The command removes expired audit events, deletes inactive block rules after the
same retention window, and deactivates expired active rules. Active permanent rules
remain until an administrator unblocks them. Redis counters and challenge state
expire independently through TTLs.
Each mutation is committed in an ordered primary-key batch (`1..10000`) to bound
transaction duration and WAL pressure.

## Public site-key rotation

The site key is public; rotating it is operational hygiene/versioning, not recovery
for a leaked server secret. In Django admin select a site-key row and choose the
rotation action. A new active key is generated and the former active key receives a
seven-day grace window.

Then update `TRIADCAPTCHA_SITE_KEY`/`VITE_TRIADCAPTCHA_SITE_KEY`, rebuild frontend
assets, deploy, and verify traffic before the grace window ends. The bootstrap
command preserves an admin rotation on restart. Revocation and grace changes are
stored in PostgreSQL; no private key is stored there.

## Server-secret rotation

There is deliberately no admin form for HMAC secrets. Rotate them in the deployment
secret manager/environment. Changing `TRIADCAPTCHA_HMAC_SECRET` immediately
invalidates outstanding challenges and technical context cookies. Changing
`TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET` starts new pseudonymous histories and makes
old manual hash rules no longer match; coordinate retention or rule recreation.

For a compromise, rotate both secrets, restart every backend process, clear only
the installation's configured Redis prefix if incident policy requires it, and
review audit. Do not paste either secret into admin notes, logs, tickets, or browser
configuration.

## Redis outage

Monitor Redis health and latency. All shipped action policies default to
`fail_closed=True`. Challenge issuance/verification never has an in-memory bypass;
an outage returns `ANTIBOT_SERVICE_UNAVAILABLE`. A deliberate fail-open policy is
appropriate only for a low-impact action and must be documented by the integrating
project.

Redis uses AOF with `appendfsync always` in the reference Compose deployment because
losing an accepted challenge tombstone across a crash would weaken the one-use
guarantee. This durability choice costs write throughput/latency; benchmark it and
use an equivalently durable HA Redis design before changing it. PostgreSQL remains
the source for long-term audit and manual/automatic block history.

`TRIADCAPTCHA_REDIS_MAX_CONNECTIONS` defaults to 32 and
`TRIADCAPTCHA_REDIS_POOL_TIMEOUT` to 0.25 seconds per backend process. Capacity
planning must use `processes × max_connections` and leave room below Redis
`maxclients`; pool exhaustion intentionally returns 503 rather than growing
connections without bound.

## Container/image pinning

The example pins reviewed multi-architecture image digests while retaining release
tags for readable updates. A production owner must scan updated digests, test backups/restores,
terminate TLS, and set CPU/memory limits appropriate to local traffic. Run
`docker compose --env-file .env -f infra/docker-compose.yml config --quiet` before
every deployment. Do not log or archive the full rendered configuration because it
contains expanded database and HMAC secrets.

The bundled listener is loopback-only HTTP and deliberately omits HSTS. Production
must terminate TLS at a separately reviewed edge; enable HSTS there only after all
covered hosts are HTTPS. Isolate `/admin/` behind VPN, private listener, or an
identity-aware proxy with MFA/SSO. The demo's admin-login rate limit is only a
coarse ceiling, not an access boundary.

CI installs Python test, audit, and release tooling from
`.github/requirements-ci.lock` with hashes and installs the library itself with
`--no-deps`; each supported Django line has its own hash-locked
`.github/requirements-django*.lock` selected by the matrix.
Regenerate the lock from `.github/requirements-ci.in`, retaining the explicitly
hashed `exceptiongroup` and `typing-extensions` markers required by older Python
matrix lanes, review the result, and validate it for every matrix Python before
merging. Node test inputs,
including the single-Chromium browser contract harness, use committed npm locks.
High/Critical image findings fail CI, including findings without a vendor fix. Any
temporary exception must instead name the CVE, rationale, owner, and expiry in a
reviewed ignore policy; there is no blanket ignore in the reference workflow.
The known Django 4.2 advisories are listed in
`.github/security-audit-ignores.txt` only for the legacy compatibility lane; CI
fails when that time-bounded policy expires, and production preflight still
rejects Django 4.2.
