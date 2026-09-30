import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from a2a.types import Message, MessageSendParams, Part, Role, SendMessageRequest, TextPart
from fastapi.testclient import TestClient

from security_agent_v2.api import app
from security_agent_v2.chainlit_app import (
    create_chat_room,
    get_or_create_chat_room,
)
from security_agent_v2.checkpointer import get_checkpointer_settings


class FakeSession:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def get(self, key: str) -> object | None:
        return self.values.get(key)

    def set(self, key: str, value: object) -> None:
        self.values[key] = value


class CheckpointerSettingsTest(unittest.TestCase):
    def test_explicit_sqlite_setting_overrides_postgres_url(self) -> None:
        settings = get_checkpointer_settings(
            {"USE_POSTGRES": "false", "POSTGRES_URL": "postgresql://localhost/db"}
        )

        self.assertEqual(settings.backend, "sqlite")

    def test_postgres_url_selects_postgres_when_setting_is_omitted(self) -> None:
        settings = get_checkpointer_settings({"POSTGRES_URL": "postgresql://localhost/db"})

        self.assertEqual(settings.backend, "postgres")

    def test_postgres_requires_a_database_url(self) -> None:
        with self.assertRaises(ValueError):
            get_checkpointer_settings({"USE_POSTGRES": "true"})


class ServerInterfacesTest(unittest.TestCase):
    def test_chat_endpoint_forwards_bearer_token_and_rejects_malformed_auth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkpoint_path = str(Path(directory) / "checkpoints.db")
            with patch.dict(
                os.environ,
                {
                    "USE_POSTGRES": "false",
                    "SQLITE_CHECKPOINT_PATH": checkpoint_path,
                    "ENABLE_LLM_ROUTER": "false",
                    "SECURITY_SCAN_MCP_URL": "",
                },
            ):
                with TestClient(app) as client:
                    with patch(
                        "security_agent_v2.api.run_chat",
                        new=AsyncMock(return_value=("ok", False)),
                    ) as run_chat:
                        response = client.post(
                            "/api/chat",
                            headers={"Authorization": "Bearer keycloak-user-token"},
                            json={
                                "thread_id": "keycloak-thread",
                                "message": "보안 점검 대상을 알려줘",
                            },
                        )
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(
                            run_chat.await_args.kwargs["mcp_auth_token"],
                            "keycloak-user-token",
                        )

                        malformed = client.post(
                            "/api/chat",
                            headers={"Authorization": "Basic invalid"},
                            json={
                                "thread_id": "keycloak-thread",
                                "message": "보안 점검 대상을 알려줘",
                            },
                        )
                        self.assertEqual(malformed.status_code, 401)
                        self.assertEqual(run_chat.await_count, 1)

    def test_rest_ui_a2a_and_sqlite_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkpoint_path = str(Path(directory) / "checkpoints.db")
            with patch.dict(
                os.environ,
                {
                    "USE_POSTGRES": "false",
                    "SQLITE_CHECKPOINT_PATH": checkpoint_path,
                    "ENABLE_LLM_ROUTER": "false",
                    "SECURITY_SCAN_MCP_URL": "",
                },
            ):
                with TestClient(app) as client:
                    self.assertEqual(client.get("/health").json(), {"status": "ok"})
                    ui_response = client.get("/ui")
                    self.assertEqual(ui_response.status_code, 200)
                    self.assertIn("Security Agent", ui_response.text)
                    self.assertEqual(
                        client.get("/ui/public/theme.json").status_code, 200
                    )
                    self.assertEqual(
                        client.get("/ui/public/shield.svg").status_code, 200
                    )
                    history_script = client.get("/ui/public/message-history.js")
                    self.assertEqual(history_script.status_code, 200)
                    self.assertIn("ArrowUp", history_script.text)
                    self.assertIn("ArrowDown", history_script.text)
                    self.assertIn("security-agent-prompt-examples", history_script.text)
                    self.assertIn("권한 있는 대상의 SCA 점검을 실행해줘", history_script.text)
                    self.assertIn("보안 점검 결과를 보여줘", history_script.text)
                    self.assertEqual(
                        client.get("/ui/public/custom.css").status_code, 200
                    )
                    self.assertIn(
                        "skills",
                        client.get("/.well-known/agent-card.json").json(),
                    )

                    rest_response = client.post(
                        "/api/chat",
                        json={"thread_id": "shared-thread", "message": "SCA scan"},
                    )
                    self.assertEqual(rest_response.status_code, 200)
                    self.assertTrue(rest_response.json()["is_paused"])

                    request = SendMessageRequest(
                        id="a2a-test",
                        jsonrpc="2.0",
                        method="message/send",
                        params=MessageSendParams(
                            message=Message(
                                role=Role.user,
                                message_id="a2a-message-test",
                                context_id="a2a-test-thread",
                                metadata={"thread_id": "shared-thread"},
                                parts=[Part(root=TextPart(text="1"))],
                            )
                        ),
                    )
                    a2a_response = client.post(
                        "/",
                        json=request.model_dump(by_alias=True, exclude_none=True),
                    )
                    self.assertEqual(a2a_response.status_code, 200)
                    self.assertEqual(
                        a2a_response.json()["result"]["status"]["state"],
                        "completed",
                    )

            self.assertTrue(Path(checkpoint_path).exists())

    def test_each_new_chat_room_gets_a_thread_and_messages_reuse_it(self) -> None:
        session = FakeSession()

        first_thread_id = create_chat_room(session)
        self.assertEqual(get_or_create_chat_room(session), first_thread_id)

        second_thread_id = create_chat_room(session)
        self.assertNotEqual(second_thread_id, first_thread_id)
        self.assertEqual(get_or_create_chat_room(session), second_thread_id)


if __name__ == "__main__":
    unittest.main()
