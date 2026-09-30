import logging
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from chainlit.utils import mount_chainlit
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from security_agent_v2.a2a_adapter import SecurityAgentExecutor, agent_card
from security_agent_v2.chat import run_chat
from security_agent_v2.checkpointer import open_checkpointer
from security_agent_v2.graph import build_agent_graph


logger = logging.getLogger(__name__)
load_dotenv()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    async with open_checkpointer() as checkpointer:
        application.state.agent_graph = build_agent_graph(checkpointer)
        try:
            yield
        finally:
            del application.state.agent_graph


app = FastAPI(title="Security Agent", lifespan=lifespan)
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["POST"],
        allow_headers=["Authorization", "Content-Type"],
    )


class ChatRequest(BaseModel):
    thread_id: str = Field(min_length=1)
    message: str = Field(min_length=1)
    user_id: str = "demo"


class ChatResponse(BaseModel):
    response: str
    is_paused: bool


class ResetRequest(BaseModel):
    thread_id: str


class ResetResponse(BaseModel):
    old_thread_id: str
    thread_id: str
    message: str


def get_agent_graph() -> Any:
    graph = getattr(app.state, "agent_graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Agent is not ready.")
    return graph


_agent_graph = get_agent_graph


@app.get("/health")
async def health_check() -> dict[str, str]:
    if getattr(app.state, "agent_graph", None) is None:
        raise HTTPException(status_code=503, detail="Agent is not ready.")
    return {"status": "ok"}


@app.post("/api/chat", response_model=ChatResponse)
@app.post("/chat", response_model=ChatResponse, include_in_schema=False)
async def chat_endpoint(
    request: ChatRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> ChatResponse:
    try:
        mcp_auth_token = _extract_bearer_token(authorization)
        response, is_paused = await run_chat(
            get_agent_graph(),
            thread_id=request.thread_id,
            message=request.message,
            user_id=request.user_id,
            mcp_auth_token=mcp_auth_token,
        )
    except HTTPException:
        raise
    except Exception as error:
        logger.exception("Security Agent chat execution failed")
        raise HTTPException(
            status_code=500, detail="Security Agent chat execution failed."
        ) from error
    return ChatResponse(response=response, is_paused=is_paused)


def _extract_bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token.strip()
        or any(character.isspace() for character in token.strip())
    ):
        raise HTTPException(
            status_code=401,
            detail="Authorization must use a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


@app.post("/reset", response_model=ResetResponse)
async def reset_chat(request: ResetRequest) -> ResetResponse:
    """Start a fresh conversation by issuing a new checkpointer thread ID."""
    return ResetResponse(
        old_thread_id=request.thread_id,
        thread_id=str(uuid.uuid4()),
        message="새 대화가 시작되었습니다.",
    )


def _graph_provider() -> Any:
    return get_agent_graph()


a2a_application = A2AStarletteApplication(
    agent_card=agent_card,
    http_handler=DefaultRequestHandler(
        agent_executor=SecurityAgentExecutor(_graph_provider),
        task_store=InMemoryTaskStore(),
    ),
)
a2a_application.add_routes_to_app(app)
mount_chainlit(
    app=app,
    target=str(Path(__file__).with_name("chainlit_app.py")),
    path="/ui",
)


def run() -> None:
    load_dotenv()
    uvicorn.run(
        "security_agent_v2.api:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8001")),
    )


if __name__ == "__main__":
    run()
