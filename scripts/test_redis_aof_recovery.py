"""Validate attempt reservation and replay tombstones across an isolated Redis restart."""

from __future__ import annotations

import os
import subprocess
import time
import uuid

import redis
from triadcaptcha_django.redis_backend import (
    CONSUME_ATTEMPT_SCRIPT,
    CREATE_ATTEMPT_SCRIPT,
    ISSUE_ATTEMPT_SCRIPT,
)

IMAGE = os.environ["TRIADCAPTCHA_TEST_REDIS_AOF_IMAGE"]
suffix = uuid.uuid4().hex[:12]
container_name = f"triadcaptcha-aof-{suffix}"
volume_name = f"triadcaptcha-aof-{suffix}"


def docker(*args: str, capture: bool = False) -> str:
    completed = subprocess.run(
        ["docker", *args],
        check=True,
        capture_output=capture,
        text=True,
    )
    return completed.stdout.strip() if capture else ""


def start() -> redis.Redis:
    docker(
        "run",
        "--detach",
        "--name",
        container_name,
        "--publish",
        "127.0.0.1::6379",
        "--volume",
        f"{volume_name}:/data",
        IMAGE,
        "redis-server",
        "--appendonly",
        "yes",
        "--appendfsync",
        "always",
        "--maxmemory-policy",
        "noeviction",
    )
    port = int(docker("port", container_name, "6379/tcp", capture=True).rsplit(":", 1)[1])
    client = redis.Redis(host="127.0.0.1", port=port, decode_responses=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if client.ping():
                return client
        except redis.RedisError:
            time.sleep(0.1)
    raise RuntimeError("Redis did not become ready before the bounded deadline")


def create_issued(client: redis.Redis, prefix: str, marker: str) -> tuple[str, str]:
    attempt_key = f"{prefix}:attempt"
    challenge_key = f"{prefix}:challenge"
    assert client.eval(
        CREATE_ATTEMPT_SCRIPT,
        1,
        attempt_key,
        "register",
        "site-marker",
        "identity-hmac",
        "context-hmac",
        300,
    ) == 1
    assert client.eval(
        ISSUE_ATTEMPT_SCRIPT,
        2,
        attempt_key,
        challenge_key,
        "register",
        "site-marker",
        "context-hmac",
        f"{prefix}-jti",
        marker,
        300,
        "site-marker",
        300,
    ) == 1
    return attempt_key, challenge_key


def consume(client: redis.Redis, prefix: str, marker: str) -> int:
    return int(
        client.eval(
            CONSUME_ATTEMPT_SCRIPT,
            4,
            f"{prefix}:attempt",
            f"{prefix}:challenge",
            f"{prefix}:challenge-used",
            f"{prefix}:attempt-used",
            f"{prefix}-jti",
            marker,
            300,
        )
    )


def main() -> None:
    marker = "register|context-hmac|site-marker"
    try:
        first = start()
        create_issued(first, "unconsumed", marker)
        create_issued(first, "consumed", marker)
        assert consume(first, "consumed", marker) == 1
        docker("stop", "--time", "10", container_name)
        docker("rm", container_name)

        restarted = start()
        assert consume(restarted, "unconsumed", marker) == 1
        assert consume(restarted, "consumed", marker) == 2
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["docker", "volume", "rm", "--force", volume_name],
            check=False,
            capture_output=True,
        )


if __name__ == "__main__":
    main()
