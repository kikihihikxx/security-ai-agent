from collections.abc import Mapping
from typing import Any

from langgraph.types import Command

from security_agent_v2.mcp_auth import use_request_mcp_auth_token


def _is_paused(state: Any) -> bool:
    return bool(state.next) or any(task.interrupts for task in state.tasks)


def _interrupt_message(result: Mapping[str, Any]) -> str | None:
    interrupts = result.get("__interrupt__", ())
    if not interrupts:
        return None
    value = getattr(interrupts[0], "value", None)
    return value.get("message") if isinstance(value, dict) else None


async def run_chat(
    graph: Any,
    *,
    thread_id: str,
    message: str,
    user_id: str,
    mcp_auth_token: str | None = None,
) -> tuple[str, bool]:
    """Run or resume a conversation on its persistent LangGraph thread."""
    config = {"configurable": {"thread_id": thread_id}}
    with use_request_mcp_auth_token(mcp_auth_token):
        state = await graph.aget_state(config)

        if _is_paused(state):
            result = await graph.ainvoke(Command(resume=message), config)
        else:
            result = await graph.ainvoke(
                {
                    "messages": [("user", message)],
                    "jwt_claims": {"user_id": user_id, "roles": ["developer"]},
                },
                config,
            )

        response = _interrupt_message(result)
        messages = result.get("messages", [])
        if response is None and messages:
            latest_message = messages[-1]
            response = (
                str(latest_message.content)
                if hasattr(latest_message, "content")
                else str(latest_message[1])
            )

        updated_state = await graph.aget_state(config)
        return response or "", _is_paused(updated_state)
