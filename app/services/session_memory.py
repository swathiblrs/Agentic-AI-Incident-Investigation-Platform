from __future__ import annotations

import json
from collections import defaultdict

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings


class SessionMemory:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._fallback: dict[str, list[dict[str, str]]] = defaultdict(list)
        try:
            self.redis: Redis | None = Redis.from_url(
                self.settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
            )
            self.redis.ping()
        except RedisError:
            self.redis = None

    def append(self, session_id: str, role: str, content: str) -> None:
        item = {"role": role, "content": content}
        if self.redis is not None:
            try:
                self.redis.rpush(self._key(session_id), json.dumps(item))
                self.redis.expire(self._key(session_id), 60 * 60 * 24 * 7)
                return
            except RedisError:
                pass
        self._fallback[session_id].append(item)

    def get(self, session_id: str) -> list[dict[str, str]]:
        if self.redis is not None:
            try:
                return [json.loads(item) for item in self.redis.lrange(self._key(session_id), 0, -1)]
            except (RedisError, json.JSONDecodeError):
                pass
        return list(self._fallback[session_id])

    def clear(self, session_id: str) -> None:
        if self.redis is not None:
            try:
                self.redis.delete(self._key(session_id))
            except RedisError:
                pass
        self._fallback.pop(session_id, None)

    @staticmethod
    def _key(session_id: str) -> str:
        return f"security-agent:session:{session_id}"
