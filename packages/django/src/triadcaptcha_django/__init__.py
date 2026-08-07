"""Public API for the TriadCAPTCHA Django integration."""

from __future__ import annotations

from typing import Any

__version__ = "0.1.1"


def evaluate(*args: Any, **kwargs: Any):
    """Evaluate a request without importing Django models during app discovery."""

    from .service import evaluate as _evaluate

    return _evaluate(*args, **kwargs)


def record_outcome(*args: Any, **kwargs: Any):
    """Record a server-observed business outcome for later risk decisions."""

    from .service import record_outcome as _record_outcome

    return _record_outcome(*args, **kwargs)


__all__ = ["__version__", "evaluate", "record_outcome"]
