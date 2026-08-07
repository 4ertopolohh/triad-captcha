from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

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


class RedisUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=4)
def _client_for(url: str, timeout: float):
    return redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=timeout,
        socket_timeout=timeout,
        health_check_interval=30,
    )


def get_redis_client():
    config = get_settings()
    return _client_for(config.redis_url, config.redis_socket_timeout)


def clear_client_cache() -> None:
    _client_for.cache_clear()


@dataclass(frozen=True)
class RateValue:
    count: int
    ttl: int


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
