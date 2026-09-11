# TriadCAPTCHA

TriadCAPTCHA is a reusable, self-hosted anti-bot layer for React + Django
applications. Each integrating project runs it inside its own backend, PostgreSQL,
Redis, and Docker Compose deployment. It has no hosted control plane, external
analytics, third-party domain, visual puzzle, checkbox, or CAPTCHA window.

Normal low-risk requests pass without proof-of-work. Medium-risk requests receive a
stable challenge-required response; the React SDK solves a short ALTCHA PoW v2
challenge in a Web Worker and retries once. High-risk requests are temporarily
blocked. All reputation, counters, and audit history are local to one installation.

TriadCAPTCHA is defence in depth—not a claim of global IP reputation, worldwide
reCAPTCHA-equivalent telemetry, volumetric DDoS protection, or certainty that a
request came from a human.

## What is included

- `triadcaptcha_django`: reusable app, migrations, ordinary-view decorator,
  explicit evaluation service, same-origin challenge endpoint, Django admin,
  HMAC pseudonymization, adaptive risk engine, ALTCHA server verification, and
  Redis replay/rate enforcement.
- `@triadcaptcha/react`: React 18/19 hook and Fetch wrapper, local Web Worker,
  same-origin-by-default enforcement with exact trusted origins, one automatic retry, stable typed errors, and bounded
  weak interaction signals.
- PostgreSQL 17 + Redis 7.4 + Django + built React demo behind Nginx Compose.
- Correctly separated Nginx `http`- and `server`-context rate-limit snippets.
- Python/React tests, compatibility matrices, lint/typecheck/build checks, package
  validation, demo smoke checks, and CI—with no publish or deploy step.

See [architecture](docs/architecture.md), [public HTTP contract](docs/public-contract.md),
[privacy](docs/privacy.md), and [operations](docs/operations.md).

## Supported versions

- Python `3.10–3.14` as allowed by the selected Django release.
- Django `>=4.2,<6.2`; use supported Django 5.2 LTS or 6.1 in production. Django
  4.2 is a tested legacy migration lane but is no longer upstream-supported.
- React `^18.2.0 || ^19.0.0`; CI exercises React 18.3 and 19.
- ALTCHA Python `>=2.1.0,<3`. Version 2.0.x is intentionally excluded due to the
  upstream PoW v2 security advisory.

The detailed matrix and the official sources checked before implementation are in
[docs/compatibility.md](docs/compatibility.md).

## Run the complete demo

Copy the environment template and replace every `CHANGE_ME` value. Generate each
server secret independently; never reuse the Django, challenge-HMAC, identifier-HMAC,
or database secrets.

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose --env-file .env -f infra/docker-compose.yml config --quiet
docker compose --env-file .env -f infra/docker-compose.yml up --build
```

Open <http://localhost:8080>. The demo has registration, login, and lead forms; the
login-only demonstration password is `demo-password`. Create a local admin user:

```bash
docker compose --env-file .env -f infra/docker-compose.yml exec backend \
  python manage.py createsuperuser
```

Redis has no published host port. PostgreSQL and Redis data use named volumes;
`docker compose down` preserves them. Do not add `--volumes` unless deletion is
intentional. The demo is HTTP-only; terminate TLS in the real deployment.
Accordingly, `.env.example` sets `DJANGO_SECURE_COOKIES=0` so the local browser can
return its CSRF and session cookies. Set it to `1` for HTTPS production traffic and
preserve the original client scheme at a trusted proxy edge.
Do not redirect or archive an unredacted `docker compose config` rendering: it
expands the environment and can expose every server secret. Use `--quiet` for
validation as shown above.

## Install from a private Git repository

No package has been published and this project performs no push. After a maintainer
reviews a private remote and creates local tag `v0.2.0`, install Python directly
from its subdirectory:

```bash
python -m pip install \
  "triadcaptcha-django @ git+ssh://git@HOST/ORG/triadcaptcha.git@v0.2.0#subdirectory=packages/django"
```

Poetry dependency form:

```toml
[tool.poetry.dependencies]
triadcaptcha-django = { git = "ssh://git@HOST/ORG/triadcaptcha.git", tag = "v0.2.0", subdirectory = "packages/django" }
```

Stock npm installs a Git package from the repository root and does not implement a
remote `#subdirectory` selector. Create the reviewed React subtree tag described in
[versioning](docs/versioning.md), then consume it:

```bash
npm install "git+ssh://git@HOST/ORG/triadcaptcha.git#react-v0.2.0"
```

For a checked-out private repository, `npm install /path/to/triadcaptcha/packages/react`
also works. A private CI can instead run `npm pack` inside `packages/react` and keep
the tarball in its own artifact store. Do not use a fictitious npm Git-subdirectory
URL.

## Add the Django package

Add the app and its URLs:

```python
# settings.py
INSTALLED_APPS = [
    # Django contrib apps...
    "triadcaptcha_django",
]

# urls.py
from django.urls import include, path

urlpatterns = [
    path("api/triadcaptcha/", include("triadcaptcha_django.urls")),
]
```

Set these required server values through the deployment environment:

```dotenv
TRIADCAPTCHA_SITE_KEY=tc_site_public_random_identifier
TRIADCAPTCHA_HMAC_SECRET=at_least_32_random_bytes_and_never_frontend
TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET=a_different_32_byte_or_longer_secret
TRIADCAPTCHA_REDIS_URL=redis://redis:6379/0
TRIADCAPTCHA_REDIS_MAX_CONNECTIONS=32
TRIADCAPTCHA_REDIS_POOL_TIMEOUT=0.25
TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE=Lax
TRIADCAPTCHA_TRUSTED_PROXY_NETWORKS=172.16.0.0/12
TRIADCAPTCHA_DEVELOPMENT_MODE=0
```

`SITE_KEY` is public and may be built into the frontend. It is an installation/key
version identifier, not a security secret. The two HMAC secrets must never enter
PostgreSQL, admin HTML, logs, JavaScript, or an image build argument.

Create database objects and initial action policies:

```bash
python manage.py migrate
python manage.py bootstrap_triadcaptcha --actions register login send_code password_reset comments
python manage.py check --deploy
python manage.py check_triadcaptcha_production
```

Review each action in **Django admin → TriadCAPTCHA**. Sensitive actions should keep
`fail_closed=True`. PoW defaults follow ALTCHA's PBKDF2/SHA-256 cost 5000 and
deterministic counter 5000–10000 baseline; benchmark real mobile devices and local
traffic before changing effort or risk limits.

### Protect an ordinary Django view

```python
import json

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from triadcaptcha_django import record_outcome
from triadcaptcha_django.decorators import protect


def login_identity(request):
    data = json.loads(request.body or b"{}")
    return {"type": "email", "value": data.get("email", "")}


@require_POST
@protect("login", identity_getter=login_identity)
def login(request):
    data = json.loads(request.body or b"{}")
    if not password_is_valid(data):
        record_outcome(
            request, "login", login_identity(request), outcome="password_failure"
        )
        return JsonResponse({"code": "INVALID_CREDENTIALS"}, status=401)

    record_outcome(request, "login", login_identity(request), outcome="success")
    return JsonResponse({"ok": True})
```

Passwords remain in application logic. TriadCAPTCHA receives only the selected
identity transiently and stores its domain-separated HMAC, never the raw value.
CSRF, authentication, authorization, validation, idempotency, and password storage
remain the host application's responsibilities.

### Explicit service call

```python
from triadcaptcha_django import evaluate

result = evaluate(
    request,
    action="send_code",
    identity={"type": "phone", "value": phone},
    payload=None,       # normally read from the SDK header
    metadata=None,      # normally read from the SDK header
)
if not result.allowed:
    return result.response()

# Perform the business operation only here.
```

No DRF dependency is required. The decorator also supports async Django views by
running the synchronous security decision in a thread-sensitive adapter.

## Add the React SDK

Fetch-wrapper form:

```tsx
import {
  createProtectedFetch,
  isTriadCaptchaError,
} from '@triadcaptcha/react';

const protectedFetch = createProtectedFetch({
  siteKey: import.meta.env.VITE_TRIADCAPTCHA_SITE_KEY,
});

try {
  const response = await protectedFetch(
    '/api/register/',
    {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
      body: JSON.stringify({ email, password }),
    },
    { action: 'register', metadata: { form_fill_ms: elapsedMs } },
  );
  // Handle the normal business response.
} catch (error) {
  if (isTriadCaptchaError(error)) {
    showYourLocalizedMessage(error.code, error.retryAfter);
  }
}
```

Hook form:

```tsx
const {
  protectedFetch,
  interactionProps,
  isVerifying,
} = useTriadCaptcha({ siteKey: window.TRIADCAPTCHA_SITE_KEY });

return (
  <form {...interactionProps} onSubmit={submit}>
    {/* normal local fields; no CAPTCHA component */}
    <button disabled={isVerifying}>Submit</button>
  </form>
);
```

The SDK permits same-origin HTTP(S) URLs and explicitly configured exact trusted
origins, prevents redirects from forwarding proof headers, requests a challenge only for `ANTIBOT_CHALLENGE_REQUIRED`, solves
PBKDF2/SHA in an emitted local module worker, and retries exactly once. It has no
fingerprinting or analytics. See the full [React package guide](packages/react/README.md)
and [demo source](examples/django-react-demo/frontend/src/App.tsx).

## Stable public errors

The host frontend localizes these codes: `ANTIBOT_CHALLENGE_REQUIRED`,
`ANTIBOT_RATE_LIMITED`, `ANTIBOT_BLOCKED`, `ANTIBOT_INVALID_PAYLOAD`,
`ANTIBOT_CHALLENGE_EXPIRED`, `ANTIBOT_CHALLENGE_REPLAYED`,
`ANTIBOT_SERVICE_UNAVAILABLE`, and `ANTIBOT_CONFIGURATION_ERROR`. Responses contain
only `{error: {code, retry_after?}}`; risk score and rule details stay in admin-only
audit. See the [status mapping](docs/public-contract.md#errors).

## Quality commands

```bash
python -m pip install -e "./packages/django[test,lint]" build twine
npm --prefix packages/react ci

python -m ruff check packages/django tests scripts examples/django-react-demo/backend
(cd packages/django && python -m pytest tests)
python -m pytest tests
python -m build packages/django
npm --prefix packages/react run check
npm --prefix packages/react pack --dry-run
npm --prefix examples/django-react-demo/frontend run typecheck
npm --prefix examples/django-react-demo/frontend run build
docker compose --env-file .env.example -f infra/docker-compose.yml config --quiet
```

On systems with GNU Make, `make check` runs the package and repository checks. CI
does not publish, push, or deploy any artifact.

## Repository map

```text
packages/django/                 Python reusable app, migrations, tests
packages/react/                  TypeScript React SDK, worker, tests
examples/django-react-demo/      ordinary Django + React integration
infra/docker-compose.yml         PostgreSQL, persistent Redis, backend, Nginx
infra/nginx/                     http/server snippets and demo gateway
docs/                            architecture, privacy, operations, contracts
tests/                           cross-package deployment invariants
```

## Known limits

- Local counters and history cannot identify globally distributed low-volume bots.
- Proof-of-work raises cost; it does not prove humanity and needs mobile-device
  calibration. Argon2id/Scrypt require an integrator-supplied worker in 0.1.0.
- Nginx limits and PoW do not absorb volumetric network attacks; use the host's
  infrastructure perimeter for that risk.
- PostgreSQL audit cleanup is a scheduled management command, not an internal
  scheduler.
- The reference Redis profile uses `appendfsync always` for replay durability;
  high-volume deployments must capacity-test it or provide an equivalently durable
  HA Redis topology.
- Public site-key rotation requires rebuilding/updating frontend configuration
  during the grace window. HMAC secrets rotate only through environment/secret
  management, deliberately not through admin.

Read [SECURITY.md](SECURITY.md) before production use. Version changes and private
release steps are in [CHANGELOG.md](CHANGELOG.md) and
[docs/versioning.md](docs/versioning.md).
