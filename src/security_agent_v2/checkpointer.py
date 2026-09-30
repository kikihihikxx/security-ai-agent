import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass

from dotenv import load_dotenv
from langgraph.checkpoint.base import BaseCheckpointSaver


@dataclass(frozen=True)
class CheckpointerSettings:
    backend: str
    postgres_url: str | None
    sqlite_path: str


def get_checkpointer_settings(
    environ: Mapping[str, str] | None = None,
) -> CheckpointerSettings:
    """Read checkpoint backend settings from the environment or .env file."""
    if environ is None:
        load_dotenv()
        environ = os.environ

    postgres_url = environ.get("POSTGRES_URL", "").strip() or None
    requested_backend = environ.get("USE_POSTGRES", "").strip().casefold()
    if requested_backend in {"1", "true", "yes", "on"}:
        use_postgres = True
    elif requested_backend in {"0", "false", "no", "off"}:
        use_postgres = False
    elif requested_backend:
        raise ValueError("USE_POSTGRES must be a boolean value.")
    else:
        use_postgres = postgres_url is not None

    if use_postgres and postgres_url is None:
        raise ValueError("POSTGRES_URL is required when USE_POSTGRES is enabled.")

    return CheckpointerSettings(
        backend="postgres" if use_postgres else "sqlite",
        postgres_url=postgres_url,
        sqlite_path=environ.get("SQLITE_CHECKPOINT_PATH", "checkpoints.db"),
    )


@asynccontextmanager
async def open_checkpointer(
    settings: CheckpointerSettings | None = None,
) -> AsyncIterator[BaseCheckpointSaver]:
    """Open and initialize the configured persistent LangGraph checkpointer."""
    selected = settings or get_checkpointer_settings()
    if selected.backend not in {"postgres", "sqlite"}:
        raise ValueError(f"Unsupported checkpointer backend: {selected.backend}")
    if selected.backend == "postgres":
        if selected.postgres_url is None:
            raise ValueError("POSTGRES_URL is required for the PostgreSQL checkpointer.")
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        async with AsyncPostgresSaver.from_conn_string(
            selected.postgres_url
        ) as checkpointer:
            await checkpointer.setup()
            yield checkpointer
        return

    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    async with AsyncSqliteSaver.from_conn_string(
        selected.sqlite_path
    ) as checkpointer:
        await checkpointer.setup()
        yield checkpointer
