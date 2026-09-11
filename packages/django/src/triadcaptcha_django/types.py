from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .errors import ErrorCode, PublicError


class Decision(str, Enum):
    ALLOW = "allow"
    CHALLENGE_REQUIRED = "challenge_required"
    BLOCK = "block"


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    error: PublicError | None = None
    # These fields are server-side diagnostics. ``as_public_dict`` never emits them.
    risk_score: int = 0
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def code(self) -> str | None:
        return self.error.code.value if self.error else None

    @property
    def http_status(self) -> int:
        return self.error.http_status if self.error else 200

    @property
    def retry_after(self) -> int | None:
        return self.error.retry_after if self.error else None

    def as_public_dict(self) -> dict[str, object]:
        if self.error:
            return self.error.as_dict()
        return {"ok": True}

    def response(self):
        if self.error:
            return self.error.response()
        raise ValueError("An allow result has no error response")


def allow(*, risk_score: int = 0, reasons: tuple[str, ...] = ()) -> EvaluationResult:
    return EvaluationResult(Decision.ALLOW, risk_score=risk_score, reasons=reasons)


def challenge_required(
    *, attempt: str, risk_score: int = 0, reasons: tuple[str, ...] = ()
) -> EvaluationResult:
    return EvaluationResult(
        Decision.CHALLENGE_REQUIRED,
        PublicError(ErrorCode.CHALLENGE_REQUIRED, attempt=attempt),
        risk_score=risk_score,
        reasons=reasons,
    )


def block(
    code: ErrorCode = ErrorCode.BLOCKED,
    *,
    status: int | None = None,
    retry_after: int | None = None,
    risk_score: int = 0,
    reasons: tuple[str, ...] = (),
) -> EvaluationResult:
    return EvaluationResult(
        Decision.BLOCK,
        PublicError(code, status=status, retry_after=retry_after),
        risk_score=risk_score,
        reasons=reasons,
    )
