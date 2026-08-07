from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from inspect import iscoroutinefunction
from typing import Any

from asgiref.sync import sync_to_async

from .errors import ErrorCode, PublicError
from .service import evaluate


def _resolve(getter: Callable | None, request, default: Any = None) -> Any:
    return getter(request) if getter is not None else default


def protect(
    action: str,
    *,
    identity_getter: Callable | None = None,
    payload_getter: Callable | None = None,
    metadata_getter: Callable | None = None,
):
    """Protect a regular sync or async Django view with TriadCAPTCHA."""

    def decorator(view):
        if iscoroutinefunction(view):

            @wraps(view)
            async def async_wrapper(request, *args, **kwargs):
                try:
                    identity = _resolve(identity_getter, request)
                    payload = _resolve(payload_getter, request)
                    metadata = _resolve(metadata_getter, request)
                except Exception:
                    return PublicError(ErrorCode.CONFIGURATION_ERROR).response()
                result = await sync_to_async(evaluate, thread_sensitive=True)(
                    request,
                    action,
                    identity=identity,
                    payload=payload,
                    metadata=metadata,
                )
                request.triadcaptcha_result = result
                if not result.allowed:
                    return result.response()
                return await view(request, *args, **kwargs)

            return async_wrapper

        @wraps(view)
        def sync_wrapper(request, *args, **kwargs):
            try:
                identity = _resolve(identity_getter, request)
                payload = _resolve(payload_getter, request)
                metadata = _resolve(metadata_getter, request)
            except Exception:
                return PublicError(ErrorCode.CONFIGURATION_ERROR).response()
            result = evaluate(
                request,
                action,
                identity=identity,
                payload=payload,
                metadata=metadata,
            )
            request.triadcaptcha_result = result
            if not result.allowed:
                return result.response()
            return view(request, *args, **kwargs)

        return sync_wrapper

    return decorator


triadcaptcha_protect = protect
antibot_required = protect

__all__ = ["antibot_required", "protect", "triadcaptcha_protect"]
