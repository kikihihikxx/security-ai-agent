import logging
from typing import Protocol
from uuid import uuid4

import chainlit as cl


logger = logging.getLogger(__name__)


class SessionStore(Protocol):
    def get(self, key: str) -> object | None: ...

    def set(self, key: str, value: object) -> None: ...


def create_chat_room(session: SessionStore) -> str:
    """Create a new chat room with an independent LangGraph thread ID."""
    thread_id = str(uuid4())
    session.set("thread_id", thread_id)
    return thread_id


def get_or_create_chat_room(session: SessionStore) -> str:
    thread_id = session.get("thread_id")
    if isinstance(thread_id, str) and thread_id:
        return thread_id
    return create_chat_room(session)


@cl.set_starters
async def set_starters() -> list[cl.Starter]:
    return [
        cl.Starter(
            label="보안 점검 시작",
            message="보안 점검 가능한 대상을 알려줘",
            icon="/public/shield.svg",
        ),
        cl.Starter(
            label="외부 저장소 조회",
            message="사내 연동된 외부 저장소 목록을 알려줘",
            icon="/public/repository.svg",
        ),
        cl.Starter(
            label="패키지 빌드",
            message="payment-pkg 패키지를 빌드해줘",
            icon="/public/package.svg",
        ),
    ]


@cl.on_chat_start
async def on_chat_start() -> None:
    thread_id = create_chat_room(cl.user_session)
    await cl.Message(
        content=(
            "## Security Agent에 오신 것을 환영합니다\n\n"
            "새 채팅방을 만들었습니다. 이 방의 대화 맥락은 별도 thread ID로 저장되며, "
            "왼쪽 **New Chat**으로 다른 대화를 시작할 수 있습니다.\n\n"
            f"`thread_id: {thread_id}`"
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    thread_id = get_or_create_chat_room(cl.user_session)
    user = cl.user_session.get("user")
    user_id = getattr(user, "identifier", None) or "demo"

    try:
        from security_agent_v2.api import get_agent_graph
        from security_agent_v2.chat import run_chat

        response, _ = await run_chat(
            get_agent_graph(),
            thread_id=thread_id,
            message=message.content,
            user_id=str(user_id),
        )
    except Exception:
        logger.exception("Chainlit chat execution failed")
        await cl.Message(
            content="요청 처리 중 오류가 발생했습니다. 서버 로그를 확인해주세요."
        ).send()
        return

    await cl.Message(content=response).send()
