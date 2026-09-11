# `@triadcaptcha/react`

Invisible React SDK for a self-hosted TriadCAPTCHA Django backend. It is same-origin by default and can be restricted to explicitly trusted exact origins for split frontend/API deployments. It has no widget, analytics, third-party requests, or default browser fingerprinting. Proof-of-work runs in Web Workers.

## Compatibility

- React `18.2+` and `19.x`
- modern browsers with `Worker`, `Web Crypto`, `TextEncoder`, and Fetch APIs
- ALTCHA PoW v2; the bundled worker supports `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`, `SHA-256`, `SHA-384`, and `SHA-512`

The build tool needs Node.js `20.19+`. Runtime consumers do not need Node.js. Memory-hard/custom algorithms can be enabled through `workerFactory` without changing the transport contract.

## Install from a private Git repository

From the React subtree tag described in the repository release guide:

```bash
npm install "git+ssh://git@example.com/team/triadcaptcha.git#react-v0.2.0"
```

When a registry or workspace tool supports repository subdirectories, target `packages/react`. Do not put the server HMAC secret in npm configuration or frontend environment variables. `siteKey` is public.

## Fetch wrapper

```ts
import { createProtectedFetch, isTriadCaptchaError } from '@triadcaptcha/react';

const protectedFetch = createProtectedFetch({
  siteKey: import.meta.env.VITE_TRIADCAPTCHA_SITE_KEY,
  // Omit for the safer same-origin default. Never use wildcards.
  trustedOrigins: ['https://api.example.com'],
  challengeUrl: 'https://api.example.com/api/triadcaptcha/challenge/',
});

try {
  const response = await protectedFetch(
    '/api/register/',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken,
      },
      body: JSON.stringify({ email, password }),
    },
    {
      action: 'register',
      metadata: { form_fill_ms: elapsed, focus_count: focusCount },
    },
  );
  // Parse the normal business response here.
} catch (error) {
  if (isTriadCaptchaError(error)) {
    showLocalizedError(error.code, error.retryAfter);
  }
}
```

The original request is sent first. Only `ANTIBOT_CHALLENGE_REQUIRED` with a valid
opaque `error.attempt` triggers a challenge fetch, background solve, and one retry.
A second challenge response is never retried recursively.

## React hook

```tsx
import { useTriadCaptcha } from '@triadcaptcha/react';

function LoginForm() {
  const { protectedFetch, interactionProps, isVerifying, error } =
    useTriadCaptcha({ siteKey: window.TRIADCAPTCHA_SITE_KEY });

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await protectedFetch(
      '/api/login/',
      { method: 'POST', body: form },
      {
        action: 'login',
        metadata: {
          honeypot_filled: Boolean(form.get('company_website')),
        },
      },
    );
  }

  return (
    <form {...interactionProps} onSubmit={submit}>
      {/* local form fields; render no CAPTCHA UI */}
      <button disabled={isVerifying}>Sign in</button>
      {error ? <LocalError error={error} /> : null}
    </form>
  );
}
```

`interactionProps` counts events; it never records input values or raw keystrokes. Metadata is weak evidence only and must not be the backend's sole reason for a block.

## Backend JSON and header contract

Challenge request:

```http
GET /api/triadcaptcha/challenge/?action=register
X-TriadCAPTCHA-Site-Key: public-site-key
X-TriadCAPTCHA-Metadata: base64url-json
X-TriadCAPTCHA-Attempt: opaque-attempt-from-428
```

Successful response (ALTCHA v2 camelCase fields):

```json
{
  "challenge": {
    "parameters": {
      "algorithm": "PBKDF2/SHA-256",
      "cost": 5000,
      "keyLength": 32,
      "keyPrefix": "signed-target-prefix",
      "nonce": "hex",
      "salt": "hex",
      "expiresAt": 1760000000,
      "data": { "jti": "server-issued-id" }
    },
    "signature": "server-hmac"
  }
}
```

The retry adds the same `X-TriadCAPTCHA-Attempt` and
`X-TriadCAPTCHA-Payload`, a standard Base64-encoded UTF-8 JSON object containing
`{challenge, solution}`. The Django endpoint must cryptographically verify the
ALTCHA payload, validate action/site/identity/session/expiry, and atomically consume
its attempt and JTI in Redis before business logic.

Public errors use either `{ "error": { "code": "...", "retry_after": 30 } }` or top-level `code`/`retry_after`. Status `428` is the recommended challenge-required response. The SDK exposes only stable public codes and never server-side risk reasons.

Protected and challenge URLs are required to be same-origin unless their exact HTTP(S) origin is listed in `trustedOrigins`. Wildcards, credentials, paths, queries, and fragments are rejected in trusted-origin entries. Cross-origin challenge requests use credentialed Fetch, so the backend must grant credentialed CORS only to the intended frontend origin and allow the five `X-TriadCAPTCHA-*` headers. Redirect following is disabled so proof headers cannot cross an origin boundary; use canonical Django URLs (including their trailing slash). The wrapper preserves request bodies for exactly one retry and overrides caller-supplied TriadCAPTCHA headers to prevent accidental replay.
