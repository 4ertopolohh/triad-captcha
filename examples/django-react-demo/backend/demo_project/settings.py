from __future__ import annotations

import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DEBUG = env_bool("DJANGO_DEBUG", False)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY and DEBUG:
    SECRET_KEY = "triadcaptcha-demo-only-not-for-production"
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY is required when DJANGO_DEBUG is false")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "triadcaptcha_django",
    "demo_api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "demo_project.urls"
WSGI_APPLICATION = "demo_project.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'demo.sqlite3'}",
        conn_max_age=60,
        conn_health_checks=True,
    )
}

AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = "/static/"
STATIC_ROOT = Path(os.getenv("DJANGO_STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
    }
}

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_COOKIES = env_bool("DJANGO_SECURE_COOKIES", not DEBUG)
SESSION_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_SECURE = SECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# TriadCAPTCHA reads the same names directly, but assigning them here makes the
# demo's deployment contract explicit and lets Django system checks inspect them.
TRIADCAPTCHA_SITE_KEY = os.getenv("TRIADCAPTCHA_SITE_KEY", "")
TRIADCAPTCHA_HMAC_SECRET = os.getenv("TRIADCAPTCHA_HMAC_SECRET", "")
TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET = os.getenv(
    "TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET", ""
)
TRIADCAPTCHA_REDIS_URL = os.getenv(
    "TRIADCAPTCHA_REDIS_URL", "redis://127.0.0.1:6379/0"
)
TRIADCAPTCHA_REDIS_MAX_CONNECTIONS = int(
    os.getenv("TRIADCAPTCHA_REDIS_MAX_CONNECTIONS", "32")
)
TRIADCAPTCHA_REDIS_POOL_TIMEOUT = float(
    os.getenv("TRIADCAPTCHA_REDIS_POOL_TIMEOUT", "0.25")
)
TRIADCAPTCHA_CONTEXT_COOKIE_SECURE = SECURE_COOKIES
TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE = os.getenv(
    "TRIADCAPTCHA_CONTEXT_COOKIE_SAMESITE", "Lax"
)
TRIADCAPTCHA_TRUSTED_PROXY_NETWORKS = env_list(
    "TRIADCAPTCHA_TRUSTED_PROXY_NETWORKS"
)
TRIADCAPTCHA_DEVELOPMENT_MODE = env_bool("TRIADCAPTCHA_DEVELOPMENT_MODE", False)
