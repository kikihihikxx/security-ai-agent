from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token


_request_mcp_auth_token: ContextVar[str | None] = ContextVar(
    "request_mcp_auth_token", default=None
)


def get_request_mcp_auth_token() -> str | None:
    return _request_mcp_auth_token.get()


@contextmanager
def use_request_mcp_auth_token(token: str | None) -> Iterator[None]:
    context_token: Token[str | None] = _request_mcp_auth_token.set(token)
    try:
        yield
    finally:
        _request_mcp_auth_token.reset(context_token)
