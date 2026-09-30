import os
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    Artifact,
    Message,
    Part,
    Role,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
)
from dotenv import load_dotenv

from security_agent_v2.chat import run_chat


load_dotenv()

agent_card = AgentCard(
    name="Security Agent",
    description="보안 저장소, 패키지 및 보안 점검 요청을 처리하는 에이전트입니다.",
    url=os.getenv("A2A_AGENT_URL", "http://localhost:8001"),
    version="0.1.0",
    default_input_modes=["text"],
    default_output_modes=["text"],
    capabilities=AgentCapabilities(streaming=False, push_notifications=False),
    skills=[
        AgentSkill(
            id="capability-guide",
            name="기능 안내",
            description="지원 기능, 필요한 입력 정보, 한계 및 바로 사용할 수 있는 질문 예시를 안내합니다.",
            tags=["capabilities", "help", "examples"],
            examples=[
                "너는 뭘 할 수 있니?",
                "어떤 데이터가 있어야 보안 점검할 수 있어?",
            ],
        ),
        AgentSkill(
            id="repository-management",
            name="저장소 조회 및 요청",
            description="사내·외부 저장소 조회, 패키지 다운로드 경로 안내 및 승인 기반 생성 요청을 처리합니다.",
            tags=["repository", "repo"],
            examples=[
                "연동된 외부 저장소를 알려줘",
                "fastmcp 패키지를 사내에서 다운받는 방법을 알려줘",
            ],
        ),
        AgentSkill(
            id="package-management",
            name="패키지 관리",
            description="필수 정보를 받아 패키지 baseline을 등록하고, 등록된 패키지의 빌드를 요청합니다.",
            tags=["package", "build"],
            examples=[
                "새 패키지 baseline 등록에 필요한 정보를 알려줘",
                "payment-pkg 빌드해줘",
            ],
        ),
        AgentSkill(
            id="security-scanning",
            name="보안 점검",
            description="사용 권한이 확인된 등록 대상에 SCA 또는 Secret Scan을 요청하고 점검 결과를 조회합니다.",
            tags=["security", "scan", "sca", "secret"],
            examples=[
                "payment-pkg SCA 점검을 실행해줘",
                "결제 API의 Secret Scan 결과를 알려줘",
                "조회한 결과에서 우선 조치할 항목을 정리해줘",
            ],
        ),
    ],
)


class SecurityAgentExecutor(AgentExecutor):
    def __init__(self, graph_provider: Callable[[], Any]) -> None:
        self._graph_provider = graph_provider

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.task_id is None or context.context_id is None:
            raise ValueError("A2A task and context IDs are required.")

        metadata = dict(context.metadata)
        if context.message is not None and context.message.metadata:
            metadata.update(context.message.metadata)
        thread_id = str(metadata.get("thread_id") or context.context_id)
        user_id = str(metadata.get("user_id") or "demo")
        response, is_paused = await run_chat(
            self._graph_provider(),
            thread_id=thread_id,
            message=context.get_user_input(),
            user_id=user_id,
        )

        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                task_id=context.task_id,
                context_id=context.context_id,
                artifact=Artifact(
                    artifact_id=str(uuid4()),
                    name="Security Agent response",
                    parts=[Part(root=TextPart(text=response))],
                ),
            )
        )
        status_message = None
        if response:
            status_message = Message(
                role=Role.agent,
                message_id=str(uuid4()),
                task_id=context.task_id,
                context_id=context.context_id,
                parts=[Part(root=TextPart(text=response))],
            )
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=context.task_id,
                context_id=context.context_id,
                final=True,
                status=TaskStatus(
                    state=TaskState.input_required if is_paused else TaskState.completed,
                    message=status_message,
                ),
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.task_id is None or context.context_id is None:
            raise ValueError("A2A task and context IDs are required.")
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=context.task_id,
                context_id=context.context_id,
                final=True,
                status=TaskStatus(state=TaskState.canceled),
            )
        )
