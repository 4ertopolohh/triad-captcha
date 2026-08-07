# Public HTTP contract

The contract is intentionally small and stable so the integrating application can
own all localized user-facing text. TriadCAPTCHA does not render a CAPTCHA window
or return explanatory rule details to the browser.

## Request headers

| Header | Purpose |
| --- | --- |
| `X-TriadCAPTCHA-Site-Key` | Public installation identifier |
| `X-TriadCAPTCHA-Action` | Stable action name such as `register` |
| `X-TriadCAPTCHA-Metadata` | Optional base64url UTF-8 JSON of allowlisted weak signals |
| `X-TriadCAPTCHA-Payload` | Base64 ALTCHA v2 payload on the single retry |

Metadata is optional. The supported keys are `form_fill_ms`, `focus_count`,
`input_count`, `pointer_count`, `keyboard_count`, `page_visible`,
`honeypot_filled`, and `was_autofilled`. The server bounds their values and
rejects unknown fields. Never put identity, form content, a password, or a
verification code in this header.

## Challenge

```http
GET /api/triadcaptcha/challenge/?action=register
X-TriadCAPTCHA-Site-Key: tc_live_public_identifier
```

The request uses the application's normal same-origin session cookie. A successful
response is:

```json
{
  "challenge": {
    "parameters": {},
    "signature": "..."
  },
  "site_key": "tc_live_public_identifier",
  "action": "register",
  "expires_at": 1786100000
}
```

The `challenge` object is an official ALTCHA PoW v2 challenge. Its detailed fields
belong to the pinned ALTCHA protocol; integrations should pass it to the SDK rather
than alter or interpret it.

## Errors

```json
{
  "error": {
    "code": "ANTIBOT_RATE_LIMITED",
    "retry_after": 30
  }
}
```

`retry_after` is included only when a safe, useful delay is known and is mirrored
in the HTTP `Retry-After` header. The stable mapping is:

| Code | HTTP | Meaning exposed to the integrator |
| --- | ---: | --- |
| `ANTIBOT_CHALLENGE_REQUIRED` | 428 | SDK may obtain/solve one challenge and retry once |
| `ANTIBOT_RATE_LIMITED` | 429 | Try after the supplied delay |
| `ANTIBOT_BLOCKED` | 403 | Local policy temporarily denies the operation |
| `ANTIBOT_INVALID_PAYLOAD` | 400 | Missing, malformed, wrongly signed, or mismatched proof |
| `ANTIBOT_CHALLENGE_EXPIRED` | 410 | Proof expired; a fresh user attempt may obtain another |
| `ANTIBOT_CHALLENGE_REPLAYED` | 409 | Proof identifier has already been consumed |
| `ANTIBOT_SERVICE_UNAVAILABLE` | 503 | Required local protection dependency is unavailable |
| `ANTIBOT_CONFIGURATION_ERROR` | 500 | Installation/configuration is invalid |

The browser never receives the numeric risk score, matched rule, honeypot result,
pseudonymous keys, counter values, or block rationale. Those remain in protected
admin audit. Consumers should switch on `code`, not English text or status alone.

## Retry rules

The SDK retries only an original request that returned
`ANTIBOT_CHALLENGE_REQUIRED`, and only once. It does not retry blocks, rate limits,
service failures, or arbitrary 428 responses. Callers should use an idempotency key
for business operations whose network result may be ambiguous; TriadCAPTCHA cannot
make a non-idempotent application endpoint idempotent.
