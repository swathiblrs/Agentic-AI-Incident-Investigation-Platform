from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langgraph.graph.state import CompiledStateGraph

from app.core.config import get_settings
from app.storage.db import get_database_pool


class LangGraphCheckpointManager:
    """Optional Postgres-backed LangGraph checkpoint support.

    The app stays local-first by default. When Postgres is enabled and the
    checkpoint package is installed, session runs can persist graph state by
    LangGraph thread id.
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self.allowed_checkpoint_tables = {
            "checkpoints",
            "checkpoint_writes",
            "checkpoint_blobs",
        }

    async def compile_with_checkpointer(
        self,
        graph_builder_factory: Callable[[], Any],
        *,
        graph_name: str,
    ) -> CompiledStateGraph | None:
        if not self.settings.use_postgres or not self.settings.use_langgraph_checkpoints:
            return None

        pool = await get_database_pool().open()
        if pool is None:
            return None

        try:
            from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        except ImportError:
            return None

        checkpointer = AsyncPostgresSaver(pool)
        await checkpointer.setup()
        return graph_builder_factory().compile(checkpointer=checkpointer, name=graph_name)

    async def clear_thread(self, session_id: str) -> bool:
        if not self.settings.use_postgres or not self.settings.use_langgraph_checkpoints:
            return False

        pool = await get_database_pool().open()
        if pool is None:
            return False

        cleared = False
        async with pool.connection() as conn:
            for table in self.settings.langgraph_checkpoint_tables:
                if table not in self.allowed_checkpoint_tables:
                    continue
                await conn.execute(f"DELETE FROM {table} WHERE thread_id = %s", (session_id,))
                cleared = True
        return cleared
