# Changelog

All notable changes are documented here. The project uses Semantic Versioning;
the Python and React packages share a release number unless a release note says
otherwise.

## [Unreleased]

## [0.2.0] - 2026-09-11

### Security

- Bound a short-lived logical attempt to action, site key, identity, session,
  challenge reservation, and its single proof retry without double-counting the
  originating business attempt.
- Separated malformed challenge traffic from accepted-client issuance quotas,
  preserved atomic replay tombstones, and bounded invalid proofs per attempt.
- Preserved forensic audit context behind shared IPs, serialized site-key rotation,
  bounded Redis connections, and batched retention cleanup.
- Added browser security headers, safe loopback-only demo exposure, container
  resource ceilings, immutable CI/container inputs, and hashed demo dependencies.

### Changed

- Challenged clients must upgrade backend and React SDK together: HTTP 428 now
  carries `error.attempt`, and challenge/proof requests require
  `X-TriadCAPTCHA-Attempt`.
- Production preflight requires Django 5.2 or newer; Django 4.2 remains a legacy
  compatibility lane only.

## [0.1.1] - 2026-08-07

### Added

- Runtime Django settings resolver for encrypted database-backed configuration.
- Safe `ConfigurationPending` state that fails protection closed without blocking initial migrations.

### Fixed

- Bound the browser `fetch` receiver in the React SDK default client.

## [0.1.0] - 2026-08-07

### Added

- Initial reusable Django application with local adaptive risk evaluation.
- HMAC-signed, action- and session-bound ALTCHA proof-of-work challenges.
- Mandatory Redis counters, rate limits, atomic one-time challenge consumption,
  and fail-closed handling.
- React 18/19 TypeScript SDK with an invisible worker-based solver and automatic
  request retry.
- Django admin, PostgreSQL audit/configuration models, demo, Docker Compose,
  Nginx rate-limit snippets, documentation, and CI.

[Unreleased]: ../../compare/v0.2.0...HEAD
[0.2.0]: ../../compare/v0.1.1...v0.2.0
[0.1.1]: ../../compare/v0.1.0...v0.1.1
[0.1.0]: ../../releases/tag/v0.1.0
