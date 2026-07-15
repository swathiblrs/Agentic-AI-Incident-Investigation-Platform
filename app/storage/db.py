from __future__ import annotations

from functools import lru_cache

from psycopg_pool import AsyncConnectionPool

from app.core.config import get_settings


class DatabasePool:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._pool: AsyncConnectionPool | None = None

    async def open(self) -> AsyncConnectionPool | None:
        if not self.settings.use_postgres:
            return None
        if self._pool is None:
            self._pool = AsyncConnectionPool(
                self.settings.database_url,
                min_size=self.settings.db_pool_min_size,
                max_size=self.settings.db_pool_max_size,
                open=False,
            )
            await self._pool.open()
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


@lru_cache
def get_database_pool() -> DatabasePool:
    return DatabasePool()
