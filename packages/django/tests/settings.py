import os

SECRET_KEY = "django-test-secret-not-used-in-production"
DEBUG = False
USE_TZ = True
TIME_ZONE = "UTC"
ALLOWED_HOSTS = ["testserver"]
ROOT_URLCONF = "tests.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

if os.environ.get("TRIADCAPTCHA_TEST_POSTGRES") == "1":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "triadcaptcha_test"),
            "USER": os.environ.get("POSTGRES_USER", "triadcaptcha"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "triadcaptcha_test"),
            "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "triadcaptcha_django",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

STATIC_URL = "/static/"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

TRIADCAPTCHA_SITE_KEY = "tc_site_test_public_identifier_123456789"
TRIADCAPTCHA_HMAC_SECRET = "challenge-test-secret-0123456789-abcdef-0123456789"
TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET = "identifier-test-secret-fedcba-9876543210-fedcba"
TRIADCAPTCHA_REDIS_URL = "redis://127.0.0.1:6379/15"
TRIADCAPTCHA_AUDIT_ALLOW_SAMPLE_RATE = 1.0
