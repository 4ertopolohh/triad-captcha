"""Fast repository-level regression checks for deployment security invariants."""

import os
import re
import subprocess
import sys
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


def test_ci_covers_every_branch_and_has_one_required_gate() -> None:
    workflow = read(".github/workflows/ci.yml")
    assert 'branches: ["**"]' in workflow
    assert 'tags: ["v*", "react-v*"]' in workflow
    assert "pull_request:" in workflow
    assert "  ci-required:\n" in workflow
    assert "if: ${{ always() }}" in workflow
    assert 'test "$result" = success || exit 1' in workflow


def test_demo_compose_is_loopback_only_and_resource_bounded() -> None:
    compose = read("infra/docker-compose.yml")
    assert '127.0.0.1:${HTTP_PORT:-8080}:8080' in compose
    assert compose.count("pids_limit:") == 4
    assert compose.count("cpus:") == 4
    assert compose.count("mem_limit:") == 4
    assert compose.count("cap_drop:") == 4
    assert compose.count("cap_add:") == 2
    backend = compose.split("  backend:\n", 1)[1].split("  nginx:\n", 1)[0]
    assert "read_only: true" in backend
    assert "DJANGO_STATIC_ROOT: /tmp/staticfiles" in backend


def test_reference_nginx_has_a_distinct_admin_login_ceiling() -> None:
    zones = read("infra/nginx/http-rate-limits.conf")
    locations = read("infra/nginx/triadcaptcha-locations.conf")
    assert "zone=triad_admin" in zones
    assert "location = /admin/login/" in locations
    assert "limit_req zone=triad_admin" in locations


def test_reference_nginx_enforces_browser_security_headers_without_demo_hsts() -> None:
    nginx = read("infra/nginx/nginx.conf")
    locations = read("infra/nginx/triadcaptcha-locations.conf")
    headers = read("infra/nginx/security-headers.conf")
    dockerfile = read("infra/nginx/Dockerfile")

    assert "include /etc/nginx/snippets/security-headers.conf;" in nginx
    assert "include /etc/nginx/snippets/security-headers.conf;" in locations
    assert "security-headers.conf /etc/nginx/snippets/security-headers.conf" in dockerfile
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "worker-src 'self'",
        "frame-ancestors 'none'",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Frame-Options",
    ):
        assert directive in headers
    assert "Strict-Transport-Security" not in headers


def test_build_and_ci_inputs_are_immutable_and_demo_python_is_hash_locked() -> None:
    workflow = read(".github/workflows/ci.yml")
    compose = read("infra/docker-compose.yml")
    dockerfiles = (
        read("examples/django-react-demo/backend/Dockerfile"),
        read("infra/nginx/Dockerfile"),
    )
    lock = read("examples/django-react-demo/backend/requirements.lock")

    action_refs = re.findall(r"uses:\s+[^\s@]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert all("@sha256:" in line for line in compose.splitlines() if "image:" in line)
    assert all(
        "@sha256:" in line
        for dockerfile in dockerfiles
        for line in dockerfile.splitlines()
        if line.startswith("FROM ")
    )
    assert "--require-hashes" in dockerfiles[0]
    assert "--hash=sha256:" in lock
    assert not (ROOT / "examples/django-react-demo/backend/requirements.txt").exists()
    assert (ROOT / ".github/dependabot.yml").is_file()


def test_release_version_and_tag_contracts_are_consistent() -> None:
    expected = read("VERSION").strip()
    command = [sys.executable, str(ROOT / "scripts/check_versions.py")]
    current = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert current.returncode == 0, current.stderr + current.stdout

    valid_env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": f"v{expected}"}
    valid = subprocess.run(
        command, cwd=ROOT, env=valid_env, capture_output=True, text=True, check=False
    )
    assert valid.returncode == 0, valid.stderr + valid.stdout

    stale_env = {**valid_env, "GITHUB_REF_NAME": "v0.1.1"}
    stale = subprocess.run(
        command, cwd=ROOT, env=stale_env, capture_output=True, text=True, check=False
    )
    assert stale.returncode != 0
    assert "must match" in stale.stderr + stale.stdout
