# Privacy and data handling

TriadCAPTCHA processes data locally within the integrating project's deployment.
It does not send analytics or risk data to TriadCAPTCHA, ALTCHA, or another third
party.

## Data processed

For a protected request the server can transiently inspect the network address,
action, Django session key, supplied login/email/phone identity, User-Agent, result
category, and explicitly provided weak form signals. Before a stable Redis key or
PostgreSQL audit row is created:

- IP addresses and identities are HMAC-pseudonymized with a dedicated secret;
- session keys are pseudonymized;
- User-Agent is reduced to a bounded family/category rather than stored verbatim;
- metadata is allowlisted and size-limited.

The audit contains timestamps, action, decision, public error class, pseudonymous
correlation keys, score/reason categories for staff investigation, and retention
expiry. It must not contain passwords, email/SMS codes, raw email/phone values,
request bodies, secrets, cookies, or ALTCHA payloads.

Repeated forced events with the same action, classification, and pseudonymous
context are deduplicated into one row per minute using Redis. During a Redis outage,
a bounded per-process fallback prevents a single request source from turning every
fail-closed response into another PostgreSQL row. Low-risk/success events use the
configured sample rate.

## Retention

Set `ProtectionConfiguration.audit_retention_days` in Django admin to the shortest
period that satisfies the project's investigation needs. Schedule the supplied
`cleanup_triadcaptcha` management command daily. Redis records use short
per-purpose TTLs; PostgreSQL is the long-term audit store. The command also deletes
inactive block rules after the retention window; active rules are kept until they
expire or an administrator unblocks them.

## Integrator responsibilities

The project's privacy notice should describe the anti-abuse purpose, categories of
technical data, pseudonymization, retention period, lawful basis, who can access
admin audit, and any infrastructure processors used by the project. A keyed hash
is pseudonymous data, not guaranteed anonymous data, so access and deletion policy
still matter.
