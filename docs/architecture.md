# Architecture

TriadCAPTCHA is installed inside each protected Django deployment. It has no
central service, shared reputation database, third-party analytics, or external
API dependency. Reputation and audit history are local to one installation.

## Components

1. Nginx applies a coarse per-address request ceiling before Django. This is a
   perimeter control, not the risk decision.
2. `triadcaptcha_django` derives pseudonymous signals, updates Redis counters,
   evaluates local rules, and returns `allow`, `challenge_required`, or `block`.
3. PostgreSQL stores action configuration, rules, public installation-key
   versions, blocks, and bounded audit events. It is not in the challenge replay
   path.
4. Redis stores rate windows, distinct-count sets, temporary blocks, challenge
   issuance records, and one-time consumption state. Redis is mandatory.
5. `@triadcaptcha/react` sends the protected request. On a stable
   `ANTIBOT_CHALLENGE_REQUIRED` response it obtains a same-origin challenge,
   solves it in a Web Worker, and retries the request exactly once.

## Request flow

```text
React form
   │ POST /api/register  (action + site key + weak metadata)
   ▼
Nginx coarse limit
   ▼
Django evaluate ── low risk ───────────────────────────► business view
   │
   ├── high risk ─► block / rate-limit public error
   │
   └── medium risk ─► 428 ANTIBOT_CHALLENGE_REQUIRED
                              │
React GET same-origin challenge
   │ Web Worker solves ALTCHA PoW v2
   └─ POST retry + signed payload
                              │
Django verifies HMAC + expiry + site/action/session binding
   │ atomically consumes jti in Redis
   └────────────────────────────────────────────────────► business view
```

The public `SITE_KEY` selects an installation and supports safe public-key
versioning. It is not trusted as a secret. The server HMAC secret is never sent
to the client or stored in PostgreSQL.

## Challenge envelope

The ALTCHA v2 challenge is created by the official Python library in deterministic
mode. Its signed `data` binds these server-controlled values:

- a cryptographically random challenge identifier (`jti`);
- the normalized action;
- the public site-key version;
- issue/expiry context.

The browser-visible envelope contains no session or identity hash. Session/context
binding is held only in the short-lived Redis issuance record, whose marker combines
the signed `jti`, action, site-key version, and the current server-derived context.

The default algorithm is `PBKDF2/SHA-256`, which is implemented with Web Crypto
in current browsers. The default cost is 5000 with deterministic counter effort
between 5000 and 10000, matching ALTCHA's wide-compatibility baseline. Benchmark
real mobile clients before changing it. The exact counter is chosen server-side to
give predictable work. Challenge records have a short Redis TTL, issuance is rate-limited, and an
accepted identifier is atomically consumed. A valid cryptographic payload is
therefore insufficient if it is expired, belongs to another action/context, was
never issued by this installation, or was already consumed.

## Risk model

Risk is a local, explainable weighted score. Signals include action policy,
HMAC-pseudonymized network address and identity, technical session, IP+identity
pairs, request frequency, distinct IP/identity fan-out, explicit authentication
failure history, replay attempts, normalized User-Agent class, and optional weak
form metadata. No single IP, browser characteristic, or frontend signal is enough
to block by itself. Frontend metadata can raise risk but cannot lower a server
decision below trusted server signals.

The browser receives only a stable error class and optional retry delay. Full
score, counters, and matching rule identifiers stay in admin-only local audit.

## Failure semantics

Redis is a security dependency rather than a cache. If it is unavailable:

- actions marked dangerous fail closed with HTTP 503 and
  `ANTIBOT_SERVICE_UNAVAILABLE`;
- challenge issuance and verification fail closed for every action;
- the implementation never accepts a challenge without replay protection;
- a project may explicitly configure a low-impact action to fail open, but the
  shipped dangerous actions cannot silently inherit that choice.

PostgreSQL failure follows normal Django/database failure handling. Nginx limiting
continues to provide only the perimeter ceiling.

## Trust boundaries

- CSRF and authentication remain Django responsibilities.
- Forwarded addresses are considered only when the immediate peer belongs to a
  configured trusted proxy network; the chain is walked from the trusted edge.
- Passwords, verification codes, raw email/phone values, secrets, and submitted
  challenge payloads must never enter logs or event metadata.
- Admin uses Django staff/superuser permissions. There is no separate dashboard.
- Development bypasses require `DEBUG=True` as well as an explicit setting and
  are rejected by Django system checks in production.

## Non-goals

TriadCAPTCHA does not offer global IP reputation, cross-customer tracking, a bot
identity guarantee, volumetric DDoS absorption, or worldwide reCAPTCHA-equivalent
telemetry. It raises the cost of automated abuse within one locally operated
application and supplies signals for that application's policy.
