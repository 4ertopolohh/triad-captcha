"""Fast repository-level regression checks for deployment security invariants."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_redis_is_not_published_by_compose() -> None:
    compose = read("infra/docker-compose.yml")
    redis_service = compose.split("  redis:\n", 1)[1].split("  backend:\n", 1)[0]
    assert "\n    ports:" not in redis_service
    assert "redis_data:/data" in redis_service
    assert "--appendonly" in redis_service
    assert "--appendfsync\n      # Reference profile" in redis_service
    assert "      - always" in redis_service
    backend_service = compose.split("  backend:\n", 1)[1].split("  nginx:\n", 1)[0]
    assert "${TRIADCAPTCHA_REDIS_URL:?" in backend_service


def test_nginx_zone_and_location_snippets_have_correct_context() -> None:
    http_snippet = read("infra/nginx/http-rate-limits.conf")
    server_snippet = read("infra/nginx/triadcaptcha-locations.conf")
    nginx = read("infra/nginx/nginx.conf")
    assert "limit_req_zone" in http_snippet
    assert "limit_req_zone" not in server_snippet
    assert "include /etc/nginx/snippets/http-rate-limits.conf;" in nginx
    assert "$proxy_add_x_forwarded_for" not in server_snippet
    assert "X-Forwarded-For $remote_addr" in server_snippet
    assert "ANTIBOT_RATE_LIMITED" in server_snippet
    assert 'add_header Retry-After "6" always;' in server_snippet
    assert "^/api/triadcaptcha/challenge/?$" in server_snippet


def test_example_access_log_does_not_persist_raw_client_identifiers() -> None:
    nginx = read("infra/nginx/nginx.conf")
    log_format = nginx.split("log_format triad", 1)[1].split(";", 1)[0]
    assert "$remote_addr" not in log_format
    assert "$http_x_forwarded_for" not in log_format
    assert "$http_user_agent" not in log_format
    assert "$args" not in log_format


def test_server_secrets_are_separate_and_placeholders() -> None:
    example = read(".env.example")
    assert "TRIADCAPTCHA_HMAC_SECRET=CHANGE_ME" in example
    assert "TRIADCAPTCHA_IDENTIFIER_HMAC_SECRET=CHANGE_ME" in example
    assert "TRIADCAPTCHA_SITE_KEY=tc_local_CHANGE_ME" in example


def test_vulnerable_altcha_python_release_is_excluded() -> None:
    pyproject = read("packages/django/pyproject.toml")
    assert '"altcha>=2.1.0,<3"' in pyproject
