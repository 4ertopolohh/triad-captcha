from __future__ import annotations

import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass

import redis
from redis.exceptions import RedisError

from .conf import get_settings

RATE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""

SET_CARDINALITY_SCRIPT = """
local cardinality = redis.call('SCARD', KEYS[1])
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 and cardinality < tonumber(ARGV[3]) then
  redis.call('SADD', KEYS[1], ARGV[1])
  cardinality = cardinality + 1
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return cardinality
"""

CONSUME_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value then
  if value ~= ARGV[1] then
    return -1
  end
  redis.call('DEL', KEYS[1])
  redis.call('SET', KEYS[2], '1', 'EX', ARGV[2])
  return 1
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 2
end
return 0
"""

CREATE_ATTEMPT_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1],
  'state', 'pending',
  'action', ARGV[1],
  'requested_site', ARGV[2],
  'identity', ARGV[3],
  'context', ARGV[4],
  'failures', '0')
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""

ISSUE_ATTEMPT_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
if redis.call('HGET', KEYS[1], 'state') ~= 'pending'
  or redis.call('HGET', KEYS[1], 'action') ~= ARGV[1]
  or redis.call('HGET', KEYS[1], 'requested_site') ~= ARGV[2] then
  return -1
end
local old_context = redis.call('HGET', KEYS[1], 'context') or ''
if old_context ~= '' and old_context ~= ARGV[3] then
  return -1
end
if redis.call('SET', KEYS[2], ARGV[5], 'NX', 'EX', ARGV[6]) == false then
  return -2
end
redis.call('HSET', KEYS[1],
  'state', 'issued',
  'context', ARGV[3],
  'jti', ARGV[4],
  'challenge_site', ARGV[7])
redis.call('EXPIRE', KEYS[1], ARGV[8])
return 1
"""

CONSUME_ATTEMPT_SCRIPT = """
if redis.call('EXISTS', KEYS[4]) == 1 or redis.call('EXISTS', KEYS[3]) == 1 then
  return 2
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
if redis.call('HGET', KEYS[1], 'state') ~= 'issued'
  or redis.call('HGET', KEYS[1], 'jti') ~= ARGV[1] then
  return -1
end
local value = redis.call('GET', KEYS[2])
if not value then
  return 0
end
if value ~= ARGV[2] then
  return -1
end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('SET', KEYS[3], '1', 'EX', ARGV[3])
redis.call('SET', KEYS[4], '1', 'EX', ARGV[3])
return 1
"""

RECORD_ATTEMPT_FAILURE_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {0, 0}
end
local failures = tonumber(redis.call('HGET', KEYS[1], 'failures') or '0')
local limit = tonumber(ARGV[1])
if failures < limit then
  failures = failures + 1
  redis.call('HSET', KEYS[1], 'failures', failures)
end
if failures >= limit then
  redis.call('DEL', KEYS[1], KEYS[2])
  redis.call('SET', KEYS[3], 'invalid-limit', 'EX', ARGV[2])
  return {failures, 1}
end
return {failures, 0}
"""


class RedisUnavailable(RuntimeError):
    pass


def _client_for(
    url: str,
    socket_timeout: float,
    max_connections: int,
    pool_timeout: float,
):
    cache_key = (url, socket_timeout, max_connections, pool_timeout)
    with _CLIENTS_LOCK:
        cached = _CLIENTS.pop(cache_key, None)
        if cached is not None:
            _CLIENTS[cache_key] = cached
            return cached

        pool = redis.BlockingConnectionPool.from_url(
            url,
            max_connections=max(1, max_connections),
            timeout=max(0.01, pool_timeout),
            decode_responses=True,
            socket_connect_timeout=socket_timeout,
            socket_timeout=socket_timeout,
            health_check_interval=30,
        )
        client = redis.Redis(connection_pool=pool)
        _CLIENTS[cache_key] = client
        if len(_CLIENTS) > _CLIENT_CACHE_SIZE:
            _, evicted = _CLIENTS.popitem(last=False)
            evicted.connection_pool.disconnect()
        return client


_CLIENT_CACHE_SIZE = 4
_CLIENTS_LOCK = threading.RLock()
_CLIENTS: OrderedDict[tuple[str, float, int, float], redis.Redis] = OrderedDict()


def get_redis_client():
    config = get_settings()
    return _client_for(
        config.redis_url,
        config.redis_socket_timeout,
        config.redis_max_connections,
        config.redis_pool_timeout,
    )


def clear_client_cache() -> None:
    with _CLIENTS_LOCK:
        clients = tuple(_CLIENTS.values())
        _CLIENTS.clear()
    for client in clients:
        client.connection_pool.disconnect()


@dataclass(frozen=True)
class RateValue:
    count: int
    ttl: int


@dataclass(frozen=True)
class AttemptState:
    state: str
    action: str
    requested_site: str
    identity: str
    context: str
    jti: str = ""
    challenge_site: str = ""
    failures: int = 0


def key(*parts: object) -> str:
    prefix = get_settings().redis_prefix.strip(":")
    return ":".join((prefix, "v1", *(str(part) for part in parts)))


def increment(name: str, window_seconds: int) -> RateValue:
    try:
        count, ttl = get_redis_client().eval(RATE_SCRIPT, 1, name, max(1, int(window_seconds)))
        return RateValue(int(count), max(0, int(ttl)))
    except RedisError as exc:
        raise RedisUnavailable("redis rate counter failed") from exc


def cardinality(name: str, member: str, window_seconds: int, *, maximum: int) -> int:
    try:
        return int(
            get_redis_client().eval(
                SET_CARDINALITY_SCRIPT,
                1,
                name,
                member,
                max(1, int(window_seconds)),
                max(1, int(maximum)),
            )
        )
    except RedisError as exc:
        raise RedisUnavailable("redis diversity counter failed") from exc


def get_int(name: str) -> int:
    try:
        value = get_redis_client().get(name)
        return int(value) if value is not None else 0
    except (RedisError, TypeError, ValueError) as exc:
        raise RedisUnavailable("redis read failed") from exc


def delete(*names: str) -> None:
    if not names:
        return
    try:
        get_redis_client().delete(*names)
    except RedisError as exc:
        raise RedisUnavailable("redis delete failed") from exc


def reserve_challenge(jti: str, marker: str, ttl: int) -> bool:
    try:
        return bool(
            get_redis_client().set(key("challenge", jti), marker, nx=True, ex=max(1, int(ttl)))
        )
    except RedisError as exc:
        raise RedisUnavailable("redis challenge reservation failed") from exc


def consume_challenge(jti: str, marker: str, tombstone_ttl: int) -> int:
    """Atomically consume a challenge: 1=consumed, 2=replay, 0=missing, -1=mismatch."""

    try:
        return int(
            get_redis_client().eval(
                CONSUME_SCRIPT,
                2,
                key("challenge", jti),
                key("challenge-used", jti),
                marker,
                max(1, int(tombstone_ttl)),
            )
        )
    except RedisError as exc:
        raise RedisUnavailable("redis atomic challenge consume failed") from exc


def create_attempt(
    action: str,
    requested_site: str,
    identity_hash: str,
    context_hash: str,
    ttl: int,
) -> str:
    try:
        client = get_redis_client()
        for _ in range(3):
            token = secrets.token_urlsafe(32)
            created = client.eval(
                CREATE_ATTEMPT_SCRIPT,
                1,
                key("attempt", token),
                action,
                requested_site,
                identity_hash,
                context_hash,
                max(1, int(ttl)),
            )
            if int(created) == 1:
                return token
        raise RedisUnavailable("redis attempt token collision")
    except RedisError as exc:
        raise RedisUnavailable("redis attempt creation failed") from exc


def get_attempt(token: str) -> AttemptState | None:
    try:
        data = get_redis_client().hgetall(key("attempt", token))
        if not data:
            return None
        return AttemptState(
            state=str(data.get("state", "")),
            action=str(data.get("action", "")),
            requested_site=str(data.get("requested_site", "")),
            identity=str(data.get("identity", "")),
            context=str(data.get("context", "")),
            jti=str(data.get("jti", "")),
            challenge_site=str(data.get("challenge_site", "")),
            failures=int(data.get("failures", 0)),
        )
    except (RedisError, TypeError, ValueError) as exc:
        raise RedisUnavailable("redis attempt read failed") from exc


def attempt_was_used(token: str) -> bool:
    try:
        return bool(get_redis_client().exists(key("attempt-used", token)))
    except RedisError as exc:
        raise RedisUnavailable("redis attempt tombstone read failed") from exc


def closed_attempt_ttl(token: str) -> int:
    try:
        ttl = get_redis_client().ttl(key("attempt-closed", token))
        return max(0, int(ttl))
    except (RedisError, TypeError, ValueError) as exc:
        raise RedisUnavailable("redis closed attempt read failed") from exc


def record_attempt_failure(
    token: str, jti: str, limit: int, tombstone_ttl: int
) -> tuple[int, bool]:
    try:
        failures, closed = get_redis_client().eval(
            RECORD_ATTEMPT_FAILURE_SCRIPT,
            3,
            key("attempt", token),
            key("challenge-v2", jti),
            key("attempt-closed", token),
            max(1, int(limit)),
            max(1, int(tombstone_ttl)),
        )
        return int(failures), bool(closed)
    except (RedisError, TypeError, ValueError) as exc:
        raise RedisUnavailable("redis attempt failure accounting failed") from exc


def issue_attempt_challenge(
    token: str,
    *,
    action: str,
    requested_site: str,
    context_hash: str,
    jti: str,
    marker: str,
    challenge_site: str,
    challenge_ttl: int,
    attempt_ttl: int,
) -> int:
    try:
        return int(
            get_redis_client().eval(
                ISSUE_ATTEMPT_SCRIPT,
                2,
                key("attempt", token),
                key("challenge-v2", jti),
                action,
                requested_site,
                context_hash,
                jti,
                marker,
                max(1, int(challenge_ttl)),
                challenge_site,
                max(1, int(attempt_ttl)),
            )
        )
    except RedisError as exc:
        raise RedisUnavailable("redis attempt challenge issuance failed") from exc


def consume_attempt_challenge(
    token: str, jti: str, marker: str, tombstone_ttl: int
) -> int:
    try:
        return int(
            get_redis_client().eval(
                CONSUME_ATTEMPT_SCRIPT,
                4,
                key("attempt", token),
                key("challenge-v2", jti),
                key("challenge-used-v2", jti),
                key("attempt-used", token),
                jti,
                marker,
                max(1, int(tombstone_ttl)),
            )
        )
    except RedisError as exc:
        raise RedisUnavailable("redis atomic attempt consume failed") from exc


def set_temporary_block(scope: str, value_hash: str, action: str, ttl: int) -> None:
    try:
        get_redis_client().set(key("block", action, scope, value_hash), "1", ex=max(1, int(ttl)))
    except RedisError as exc:
        raise RedisUnavailable("redis temporary block failed") from exc


def temporary_block_ttl(scope: str, value_hash: str, action: str) -> int:
    if not value_hash:
        return 0
    try:
        ttl = int(get_redis_client().ttl(key("block", action, scope, value_hash)))
        return max(0, ttl)
    except RedisError as exc:
        raise RedisUnavailable("redis temporary block read failed") from exc


def clear_temporary_block(scope: str, value_hash: str, action: str | None = None) -> None:
    try:
        client = get_redis_client()
        if action:
            client.delete(key("block", action, scope, value_hash))
        else:
            pattern = key("block", "*", scope, value_hash)
            cursor = 0
            while True:
                cursor, keys = client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    client.delete(*keys)
                if cursor == 0:
                    break
    except RedisError as exc:
        raise RedisUnavailable("redis temporary block clear failed") from exc
