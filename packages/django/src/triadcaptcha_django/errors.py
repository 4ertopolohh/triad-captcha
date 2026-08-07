from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from django.http import JsonResponse


class ErrorCode(str, Enum):
    CHALLENGE_REQUIRED = "ANTIBOT_CHALLENGE_REQUIRED"
    RATE_LIMITED = "ANTIBOT_RATE_LIMITED"
    BLOCKED = "ANTIBOT_BLOCKED"
    INVALID_PAYLOAD = "ANTIBOT_INVALID_PAYLOAD"
    CHALLENGE_EXPIRED = "ANTIBOT_CHALLENGE_EXPIRED"
    CHALLENGE_REPLAYED = "ANTIBOT_CHALLENGE_REPLAYED"
    SERVICE_UNAVAILABLE = "ANTIBOT_SERVICE_UNAVAILABLE"
    CONFIGURATION_ERROR = "ANTIBOT_CONFIGURATION_ERROR"


DEFAULT_STATUS: dict[ErrorCode, int] = {
    ErrorCode.CHALLENGE_REQUIRED: 428,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.BLOCKED: 403,
    ErrorCode.INVALID_PAYLOAD: 400,
    ErrorCode.CHALLENGE_EXPIRED: 410,
    ErrorCode.CHALLENGE_REPLAYED: 409,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
    ErrorCode.CONFIGURATION_ERROR: 500,
}


@dataclass(frozen=True)
class PublicError:
    code: ErrorCode
    status: int | None = None
    retry_after: int | None = None

    @property
    def http_status(self) -> int:
        return self.status or DEFAULT_STATUS[self.code]

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"code": self.code.value}
        if self.retry_after is not None:
            data["retry_after"] = max(0, int(self.retry_after))
        return {"error": data}

    def response(self) -> JsonResponse:
        response = JsonResponse(self.as_dict(), status=self.http_status)
        if self.retry_after is not None:
            response["Retry-After"] = str(max(0, int(self.retry_after)))
        response["Cache-Control"] = "no-store"
        return response


class TriadCaptchaFailure(Exception):
    """Internal exception carrying only a stable, browser-safe public error."""

    def __init__(
        self,
        code: ErrorCode,
        *,
        status: int | None = None,
        retry_after: int | None = None,
        internal_reason: str = "",
    ) -> None:
        self.public_error = PublicError(code, status=status, retry_after=retry_after)
        self.internal_reason = internal_reason
        super().__init__(code.value)
