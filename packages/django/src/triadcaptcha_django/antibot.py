"""Explicit service namespace for integrations preferring ``antibot.evaluate``."""

from .service import evaluate, record_outcome

__all__ = ["evaluate", "record_outcome"]
