"""Verify that all independently installable artifacts share the release version."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$"
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require_match(pattern: str, content: str, source: str) -> str:
    match = re.search(pattern, content, flags=re.MULTILINE)
    if match is None:
        raise SystemExit(f"Could not read a release version from {source}")
    return match.group(1)


def main() -> None:
    expected = read("VERSION").strip()
    if SEMVER.fullmatch(expected) is None:
        raise SystemExit(f"VERSION is not valid SemVer: {expected!r}")

    pyproject = read("packages/django/pyproject.toml")
    django_init = read("packages/django/src/triadcaptcha_django/__init__.py")
    react_package = json.loads(read("packages/react/package.json"))
    react_lock = json.loads(read("packages/react/package-lock.json"))

    versions = {
        "packages/django/pyproject.toml": require_match(
            r'^version\s*=\s*"([^"]+)"$', pyproject, "packages/django/pyproject.toml"
        ),
        "packages/django/src/triadcaptcha_django/__init__.py": require_match(
            r'^__version__\s*=\s*"([^"]+)"$',
            django_init,
            "packages/django/src/triadcaptcha_django/__init__.py",
        ),
        "packages/react/package.json": react_package.get("version"),
        "packages/react/package-lock.json": react_lock.get("version"),
        "packages/react/package-lock.json workspace": react_lock.get("packages", {})
        .get("", {})
        .get("version"),
    }

    mismatches = {
        source: version for source, version in versions.items() if version != expected
    }
    if mismatches:
        details = ", ".join(
            f"{source}={version!r}" for source, version in mismatches.items()
        )
        raise SystemExit(f"Release versions must match VERSION={expected!r}: {details}")

    if f"## [{expected}]" not in read("CHANGELOG.md"):
        raise SystemExit(f"CHANGELOG.md has no release heading for {expected}")
    if f"## {expected}" not in read("packages/react/CHANGELOG.md"):
        raise SystemExit(
            f"packages/react/CHANGELOG.md has no release heading for {expected}"
        )

    if os.getenv("GITHUB_REF_TYPE") == "tag":
        tag = os.getenv("GITHUB_REF_NAME", "")
        allowed_tags = {f"v{expected}", f"react-v{expected}"}
        if tag not in allowed_tags:
            allowed = " or ".join(sorted(allowed_tags))
            raise SystemExit(f"Release tag {tag!r} must match {allowed}")

    print(f"Release metadata is consistent at {expected}")


if __name__ == "__main__":
    main()
