# Django + React demo

This example protects three ordinary Django `JsonResponse` endpoints—registration,
login, and a lead form—without Django REST Framework. The React application uses
the hook API and renders its own Russian messages from stable error codes. No
CAPTCHA UI is mounted.

## Docker Compose

From the repository root:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Put independent generated values into every CHANGE_ME secret in .env.
docker compose --env-file .env -f infra/docker-compose.yml config --quiet
docker compose --env-file .env -f infra/docker-compose.yml up --build
```

Open <http://localhost:8080>. The login form accepts `demo-password`; other values
record a password failure so repeated-failure risk can be observed.
The published port is bound to `127.0.0.1` by default. Use an SSH tunnel for a
remote demo; do not widen it to every interface.

The example deliberately uses `DJANGO_SECURE_COOKIES=0` on localhost HTTP. Set it
to `1` when the deployment is served through HTTPS; otherwise browsers will not
send the session/CSRF cookies needed by the protected retry.
Keep `--quiet`: a full rendered Compose configuration expands secret values and
must not be written to a terminal log or CI artifact.

Create an admin user with:

```bash
docker compose --env-file .env -f infra/docker-compose.yml exec backend \
  python manage.py createsuperuser
```

Then open <http://localhost:8080/admin/> and inspect the **TriadCAPTCHA** section.

The CI smoke test also executes the complete demo request flow against Redis:
challenge-required response, server-issued ALTCHA solution, protected retry, and
replay rejection.

## Local development

Run PostgreSQL and Redis locally (or point the environment variables at development
instances), then:

```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r examples/django-react-demo/backend/requirements.lock
.venv/bin/python -m pip install --no-deps -e packages/django
python examples/django-react-demo/backend/manage.py migrate
python examples/django-react-demo/backend/manage.py bootstrap_triadcaptcha \
  --actions register login lead
python examples/django-react-demo/backend/manage.py runserver 8000
```

In another shell:

```bash
npm --prefix packages/react install
npm --prefix packages/react run build
npm --prefix examples/django-react-demo/frontend install
npm --prefix examples/django-react-demo/frontend run dev
```

Set `VITE_TRIADCAPTCHA_SITE_KEY` to the same public value as
`TRIADCAPTCHA_SITE_KEY`. On Windows use `.venv\Scripts\python.exe` instead of
`.venv/bin/python`.
