from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .audit import AuditSignals
from .models import BlockRule, ProtectedAction
from .redis_backend import (
    cardinality,
    get_int,
    increment,
    key,
    set_temporary_block,
    temporary_block_ttl,
)
from .signals import (
    get_context_binding,
    hash_identity,
    hash_ip,
    hash_pair,
    normalize_user_agent,
)


@dataclass(frozen=True)
class RequestSignals:
    ip_hash: str
    identity_hash: str
    session_hash: str
    ip_identity_hash: str
    user_agent_family: str

    def audit(self) -> AuditSignals:
        return AuditSignals(
            ip_hash=self.ip_hash,
            identity_hash=self.identity_hash,
            session_hash=self.session_hash,
            ip_identity_hash=self.ip_identity_hash,
            user_agent_family=self.user_agent_family,
        )


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    reasons: tuple[str, ...]
    categories: frozenset[str]
    should_block: bool
    existing_block: bool
    retry_after: int | None = None


def collect_signals(request, identity=None) -> RequestSignals:
    ip_hash = hash_ip(request)
    identity_hash = hash_identity(identity)
    session_hash = get_context_binding(request, create=False).context_hash
    return RequestSignals(
        ip_hash=ip_hash,
        identity_hash=identity_hash,
        session_hash=session_hash,
        ip_identity_hash=hash_pair(ip_hash, identity_hash),
        user_agent_family=normalize_user_agent(request),
    )


def failure_keys(policy: ProtectedAction, signals: RequestSignals) -> tuple[str, ...]:
    keys = []
    if signals.identity_hash:
        keys.append(key("failure", policy.action, "identity", signals.identity_hash))
    if signals.session_hash:
        keys.append(key("failure", policy.action, "session", signals.session_hash))
    if signals.ip_identity_hash:
        keys.append(key("failure", policy.action, "pair", signals.ip_identity_hash))
    return tuple(keys)


def replay_key(policy: ProtectedAction, signals: RequestSignals) -> str:
    binding = signals.session_hash or signals.ip_identity_hash or signals.identity_hash
    return key("replay", policy.action, binding or "unbound")


def _effective_manual_rules(policy: ProtectedAction, signals: RequestSignals):
    now = timezone.now()
    values = {
        BlockRule.Scope.IP: signals.ip_hash,
        BlockRule.Scope.IDENTITY: signals.identity_hash,
        BlockRule.Scope.SESSION: signals.session_hash,
        BlockRule.Scope.IP_IDENTITY: signals.ip_identity_hash,
    }
    clauses = Q(pk__in=[])
    for scope, value_hash in values.items():
        if value_hash:
            clauses |= Q(scope=scope, value_hash=value_hash)
    if not clauses:
        return []
    return list(
        BlockRule.objects.filter(active=True)
        .filter(Q(action=policy) | Q(action__isnull=True))
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .filter(clauses)
        .only("scope", "source", "reason_code")
    )


def check_authoritative_blocks(
    policy: ProtectedAction, signals: RequestSignals
) -> RiskAssessment:
    """Recheck block state without observing another business attempt."""

    reasons: list[str] = []
    categories: set[str] = set()
    retry_after = 0
    hard_block = False
    for scope, value_hash in (
        (BlockRule.Scope.IP_IDENTITY, signals.ip_identity_hash),
        (BlockRule.Scope.SESSION, signals.session_hash),
        (BlockRule.Scope.IDENTITY, signals.identity_hash),
        (BlockRule.Scope.IP, signals.ip_hash),
    ):
        ttl = temporary_block_ttl(scope, value_hash, policy.action)
        if ttl:
            retry_after = max(retry_after, ttl)
            reasons.append(f"temporary_block_{scope}")
            categories.add("ip" if scope == BlockRule.Scope.IP else "temporary_block")
            if scope != BlockRule.Scope.IP:
                hard_block = True

    for rule in _effective_manual_rules(policy, signals):
        reasons.append(f"block_rule_{rule.scope}")
        categories.add("ip" if rule.scope == BlockRule.Scope.IP else "manual")
        if rule.scope != BlockRule.Scope.IP:
            hard_block = True

    return RiskAssessment(
        score=0,
        reasons=tuple(reasons),
        categories=frozenset(categories),
        should_block=hard_block,
        existing_block=hard_block,
        retry_after=retry_after or None,
    )


def assess_risk(
    policy: ProtectedAction,
    signals: RequestSignals,
    metadata: dict,
) -> RiskAssessment:
    score = int(policy.base_risk_score)
    reasons: list[str] = []
    categories: set[str] = set()
    retry_after = 0
    hard_block = False
    limit_crossed = False

    # A temporary block tied to an identity/session/pair is authoritative. An IP-only
    # block remains an input signal and never blocks by itself.
    for scope, value_hash in (
        (BlockRule.Scope.IP_IDENTITY, signals.ip_identity_hash),
        (BlockRule.Scope.SESSION, signals.session_hash),
        (BlockRule.Scope.IDENTITY, signals.identity_hash),
        (BlockRule.Scope.IP, signals.ip_hash),
    ):
        ttl = temporary_block_ttl(scope, value_hash, policy.action)
        if ttl:
            retry_after = max(retry_after, ttl)
            reasons.append(f"temporary_block_{scope}")
            categories.add("ip" if scope == BlockRule.Scope.IP else "temporary_block")
            if scope == BlockRule.Scope.IP:
                score += 45
            else:
                hard_block = True

    for rule in _effective_manual_rules(policy, signals):
        reasons.append(f"block_rule_{rule.scope}")
        if rule.scope == BlockRule.Scope.IP:
            score += 45
            categories.add("ip")
        else:
            hard_block = True
            categories.add("manual")

    window = policy.rate_window_seconds
    rates: list[tuple[str, int, int, str, int]] = [
        ("ip_rate", policy.ip_limit, 25, "ip", 0),
    ]
    ip_rate = increment(key("rate", policy.action, "ip", signals.ip_hash), window)
    rates[0] = (*rates[0][0:4], ip_rate.count)
    retry_after = max(retry_after, ip_rate.ttl if ip_rate.count > policy.ip_limit else 0)

    if signals.identity_hash:
        value = increment(key("rate", policy.action, "identity", signals.identity_hash), window)
        rates.append(("identity_rate", policy.identity_limit, 30, "identity", value.count))
        if value.count > policy.identity_limit:
            retry_after = max(retry_after, value.ttl)
    if signals.session_hash:
        value = increment(key("rate", policy.action, "session", signals.session_hash), window)
        rates.append(("session_rate", policy.session_limit, 25, "session", value.count))
        if value.count > policy.session_limit:
            retry_after = max(retry_after, value.ttl)
    if signals.ip_identity_hash:
        value = increment(key("rate", policy.action, "pair", signals.ip_identity_hash), window)
        rates.append(("ip_identity_rate", policy.ip_identity_limit, 40, "pair", value.count))
        if value.count > policy.ip_identity_limit:
            retry_after = max(retry_after, value.ttl)

    for reason, limit, weight, category, count in rates:
        if count > limit:
            limit_crossed = True
            score += weight
            if count > limit * 2:
                score += 15
            reasons.append(reason)
            categories.add(category)

    diversity_window = min(86400, max(600, window * 10))
    if signals.identity_hash:
        identities = cardinality(
            key("diversity", policy.action, "ip", signals.ip_hash),
            signals.identity_hash,
            diversity_window,
            maximum=policy.identities_per_ip_limit + 1,
        )
        if identities > policy.identities_per_ip_limit:
            limit_crossed = True
            score += 35
            reasons.append("many_identities_per_ip")
            categories.add("diversity")

        ips = cardinality(
            key("diversity", policy.action, "identity", signals.identity_hash),
            signals.ip_hash,
            diversity_window,
            maximum=policy.ips_per_identity_limit + 1,
        )
        if ips > policy.ips_per_identity_limit:
            limit_crossed = True
            score += 35
            reasons.append("many_ips_per_identity")
            categories.add("diversity")

    failures = max((get_int(item) for item in failure_keys(policy, signals)), default=0)
    if failures >= policy.failure_limit:
        limit_crossed = True
        score += 35 + min(15, failures - policy.failure_limit)
        reasons.append("repeated_business_failures")
        categories.add("failure")

    replay_count = get_int(replay_key(policy, signals))
    if replay_count:
        limit_crossed = True
        score += 45 + min(20, replay_count * 5)
        reasons.append("previous_challenge_replay")
        categories.add("replay")

    if signals.user_agent_family in {"bot", "curl", "wget", "missing"}:
        score += 8
        reasons.append("unusual_user_agent_family")
        categories.add("user_agent")

    if metadata.get("honeypot_filled") is True:
        score += 30
        reasons.append("honeypot_filled")
        categories.add("frontend")
    if "form_fill_ms" in metadata and int(metadata["form_fill_ms"]) < 700:
        score += 15
        reasons.append("very_fast_form_fill")
        categories.add("frontend")
    if metadata.get("input_count") == 0 and "input_count" in metadata:
        score += 5
        reasons.append("no_input_events")
        categories.add("frontend")

    if limit_crossed:
        score = max(score, policy.challenge_threshold)
    score = min(100, max(0, score))
    stronger = categories - {"ip", "frontend", "user_agent"}
    can_adaptively_block = bool(
        {"pair", "diversity", "replay", "temporary_block", "manual"} & stronger
        or len(stronger) >= 2
    )
    should_block = hard_block or (score >= policy.block_threshold and can_adaptively_block)
    return RiskAssessment(
        score=score,
        reasons=tuple(reasons),
        categories=frozenset(categories),
        should_block=should_block,
        existing_block=hard_block,
        retry_after=retry_after or None,
    )


def create_temporary_block(
    policy: ProtectedAction,
    signals: RequestSignals,
    reasons: tuple[str, ...],
) -> int:
    if signals.ip_identity_hash:
        scope, value_hash = BlockRule.Scope.IP_IDENTITY, signals.ip_identity_hash
    elif signals.session_hash:
        scope, value_hash = BlockRule.Scope.SESSION, signals.session_hash
    elif signals.identity_hash:
        scope, value_hash = BlockRule.Scope.IDENTITY, signals.identity_hash
    else:
        # Deliberately never create an automatic IP-only block.
        return 0
    ttl = policy.temporary_block_seconds
    set_temporary_block(scope, value_hash, policy.action, ttl)
    expires_at = timezone.now() + timedelta(seconds=ttl)
    existing = BlockRule.objects.filter(
        action=policy, scope=scope, value_hash=value_hash, active=True
    ).first()
    if existing:
        existing.source = BlockRule.Source.AUTOMATIC
        existing.reason_code = "adaptive_high_risk"
        existing.internal_reason = ",".join(reasons)[:2000]
        existing.expires_at = expires_at
        existing.save(update_fields=("source", "reason_code", "internal_reason", "expires_at"))
    else:
        BlockRule.objects.create(
            action=policy,
            scope=scope,
            value_hash=value_hash,
            source=BlockRule.Source.AUTOMATIC,
            reason_code="adaptive_high_risk",
            internal_reason=",".join(reasons)[:2000],
            expires_at=expires_at,
        )
    return ttl
