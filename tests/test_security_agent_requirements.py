import os
import unittest
import uuid
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

import httpx
from langgraph.types import Command

from security_agent_v2.graph import agent_app
from security_agent_v2.main import main as cli_main
from security_agent_v2.nodes.security_scan_node import (
    _aggregate_scan_status,
    _format_findings_report,
    _scan_result_message,
    security_scan_node,
)
from security_agent_v2.nodes.intent_classifier_node import (
    IntentClassification,
    intent_classifier_node,
)
from security_agent_v2.nodes.supervisor_node import _heuristic_route
from security_agent_v2.model import factory as llm_factory
from security_agent_v2.mcp_auth import use_request_mcp_auth_token
from security_agent_v2.tools.mcp_tools import (
    EmptyInput,
    ProductListInput,
    ScaScanInput,
    SecretScanInput,
    execute_sca_scan,
    execute_secret_scan,
    get_sca_scan_result,
    get_pg_product_list,
    get_secret_scan_result,
)
from security_agent_v2.tools import mcp_tools
from security_agent_v2.tools.mcp_tools import ScanMCPToolError


class SecurityAgentRequirementsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._router_setting = os.environ.get("ENABLE_LLM_ROUTER")
        cls._scan_mcp_url = os.environ.get("SECURITY_SCAN_MCP_URL")
        cls._scan_mcp_token = os.environ.pop("SECURITY_SCAN_MCP_AUTH_TOKEN", None)
        cls._mcp_token = os.environ.pop("SECURITY_MCP_AUTH_TOKEN", None)
        os.environ["ENABLE_LLM_ROUTER"] = "false"
        os.environ["SECURITY_SCAN_MCP_URL"] = ""

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._router_setting is None:
            os.environ.pop("ENABLE_LLM_ROUTER", None)
        else:
            os.environ["ENABLE_LLM_ROUTER"] = cls._router_setting
        if cls._scan_mcp_url is None:
            os.environ.pop("SECURITY_SCAN_MCP_URL", None)
        else:
            os.environ["SECURITY_SCAN_MCP_URL"] = cls._scan_mcp_url
        if cls._scan_mcp_token is not None:
            os.environ["SECURITY_SCAN_MCP_AUTH_TOKEN"] = cls._scan_mcp_token
        if cls._mcp_token is not None:
            os.environ["SECURITY_MCP_AUTH_TOKEN"] = cls._mcp_token

    def _config(self) -> dict:
        return {"configurable": {"thread_id": str(uuid.uuid4())}}

    def _start_scan_and_select_package(self, scan_request: str = "SCA scan") -> tuple[dict, dict]:
        config = self._config()
        initial = agent_app.invoke(
            {"messages": [("user", scan_request)], "jwt_claims": {"user_id": "demo"}},
            config,
        )
        selected = agent_app.invoke(Command(resume="1"), config)
        return config, selected

    def test_mcp_input_contracts_require_scan_context(self) -> None:
        self.assertEqual(
            {"system_id", "service_id"},
            set(SecretScanInput.model_json_schema()["required"]),
        )
        self.assertEqual(
            {"system_id", "service_id"},
            set(ScaScanInput.model_json_schema()["required"]),
        )

    def test_request_jwt_takes_precedence_for_scan_mcp_calls(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SECURITY_SCAN_MCP_URL": "http://127.0.0.1:8000/mcp",
                "SECURITY_SCAN_MCP_AUTH_TOKEN": "local-test-token",
            },
        ):
            with patch.object(
                mcp_tools, "_call_remote_tool", return_value=[]
            ) as call_remote:
                with use_request_mcp_auth_token("keycloak-user-token"):
                    mcp_tools._call_scan_server_tool("get_my_products", {})
                self.assertEqual(
                    call_remote.call_args.kwargs["auth_token"],
                    "keycloak-user-token",
                )

                mcp_tools._call_scan_server_tool("get_my_products", {})
                self.assertEqual(
                    call_remote.call_args.kwargs["auth_token"],
                    "local-test-token",
                )

    def test_get_pg_product_list_returns_package_and_product_targets(self) -> None:
        products = get_pg_product_list.invoke(ProductListInput(user_id="demo"))

        self.assertEqual(products[0]["service_id"], "sdep")
        self.assertEqual(products[0]["package_name"], "payment-pkg")
        self.assertEqual(products[1]["service_id"], "devops")
        self.assertEqual(products[1]["product_id"], "pay-api-v1")

    def test_python_package_download_uses_pypi_proxy(self) -> None:
        config = self._config()
        result = agent_app.invoke(
            {
                "messages": [("user", "fastmcp 패키지를 사내에서 다운받으려면 어떻게 해야해?")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        message = result["messages"][-1].content
        self.assertIn("fastmcp 패키지를 말씀하시는 거군요!", message)
        self.assertIn("company-pypi-proxy", message)
        self.assertIn("company-pypi-proxy/simple", message)
        self.assertIn("fastmcp", message)

    def test_scan_tools_queue_without_returning_findings(self) -> None:
        context = {
            "target_type": "package",
            "target_name": "payment-pkg",
            "system_id": "payments",
            "service_id": "sdep",
            "user_id": "demo",
        }

        secret = execute_secret_scan.invoke(SecretScanInput(**context))
        sca = execute_sca_scan.invoke(ScaScanInput(**context))

        self.assertEqual(secret["status"], "queued")
        self.assertEqual(sca["status"], "queued")
        self.assertIn("task_id", secret)
        self.assertIn("task_id", sca)
        self.assertNotIn("findings", secret)
        self.assertNotIn("findings", sca)

    def test_security_intent_routing_and_unknown_intent(self) -> None:
        self.assertEqual(_heuristic_route("secret scan"), "SecurityScanAgent")
        self.assertEqual(_heuristic_route("점검 결과 알려줘"), "SecurityScanAgent")
        self.assertEqual(_heuristic_route("외부저장소뭐있지"), "RepoAgent")
        self.assertEqual(_heuristic_route("사내 연동된 외부 저장소 어떤 게 있어?"), "RepoAgent")
        self.assertEqual(_heuristic_route("외부저장소"), "FeatureDiscovery")
        self.assertEqual(_heuristic_route("보안점검"), "FeatureDiscovery")
        self.assertEqual(_heuristic_route("hello"), "UnknownIntent")

    def test_capability_question_routes_to_support_guide(self) -> None:
        for question in (
            "너는 무슨 일을 할 수 있어? 핵심 기능 알려줘.",
            "너는 뭘 할 수 있니?",
            "너는 뭘 할 수 있어?",
            "어떤 질문을 하면 돼?",
        ):
            with self.subTest(question=question):
                self.assertEqual(_heuristic_route(question), "SupportGuide")
        self.assertEqual(
            _heuristic_route("어떤 데이터(코드, URL, 파일)를 넘겨줘야 점검이 가능해?"),
            "SupportGuide",
        )
        self.assertEqual(
            _heuristic_route("분석 가능한 항목과 한계점을 알려줘."),
            "SupportGuide",
        )

    def test_graph_classifies_input_before_routing_to_capability_guide(self) -> None:
        result = agent_app.invoke(
            {"messages": [("user", "어떤 데이터(코드, URL, 파일)를 넘겨줘야 점검이 가능해?")]},
            self._config(),
        )

        self.assertEqual(result["intent_category"], "capability_guide")
        self.assertIn("지원 기능 안내", result["messages"][-1].content)
        self.assertNotIn("입력 방법 및 한계", result["messages"][-1].content)
        self.assertNotIn("fixture/mock", result["messages"][-1].content)

    def test_what_can_you_do_shows_capabilities_and_example_questions(self) -> None:
        result = agent_app.invoke(
            {"messages": [("user", "너는 뭘 할 수 있니?")]},
            self._config(),
        )
        response = result["messages"][-1].content

        self.assertEqual(result["intent_category"], "capability_guide")
        self.assertIn("저장소 관리", response)
        self.assertIn("패키지 관리", response)
        self.assertIn("보안 점검", response)
        self.assertIn(
            "저는 오픈소스 취약점 분석(SCA), Secret Scan 점검 및 결과 조회를 할 수 있어요.",
            response,
        )
        self.assertIn("질문 예시", response)
        self.assertIn("payment-pkg SCA 점검해줘", response)
        self.assertNotIn("입력 방법 및 한계", response)
        self.assertNotIn("현재 미지원", response)
        self.assertNotIn("fixture/mock", response)

    def test_intent_classifier_uses_structured_output_when_enabled(self) -> None:
        with (
            patch.dict("os.environ", {"ENABLE_LLM_ROUTER": "true"}),
            patch.object(llm_factory, "create_llm") as create_llm,
        ):
            create_llm.return_value.with_structured_output.return_value.invoke.return_value = (
                IntentClassification(category="secret_scan")
            )

            result = intent_classifier_node({"messages": [("user", "시크릿 점검 요청")]})

        self.assertEqual(result["intent_category"], "secret_scan")
        create_llm.return_value.with_structured_output.assert_called_once_with(
            IntentClassification
        )
        create_llm.return_value.with_structured_output.return_value.invoke.assert_called_once()

    def test_capability_question_uses_llm_structured_routing(self) -> None:
        with (
            patch.dict("os.environ", {"ENABLE_LLM_ROUTER": "true"}),
            patch.object(llm_factory, "create_llm") as create_llm,
        ):
            create_llm.return_value.with_structured_output.return_value.invoke.return_value = (
                IntentClassification(category="capability_guide")
            )
            result = intent_classifier_node(
                {"messages": [("user", "너는 무슨 Agent니?")]}
            )

        self.assertEqual(result["intent_category"], "capability_guide")
        create_llm.return_value.with_structured_output.return_value.invoke.assert_called_once()

    def test_pending_feature_number_selection_skips_llm_router(self) -> None:
        with (
            patch.dict("os.environ", {"ENABLE_LLM_ROUTER": "true"}),
            patch.object(llm_factory, "create_llm") as create_llm,
        ):
            result = intent_classifier_node(
                {
                    "messages": [("user", "1")],
                    "pending_feature_options": [
                        {
                            "route": "SecurityScanAgent",
                            "request": "Secret Scan 보안점검 실행해줘",
                        }
                    ],
                }
            )

        self.assertEqual(result["intent_category"], "feature_discovery")
        create_llm.assert_not_called()

    def test_security_scan_explains_missing_mcp_auth_token(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SECURITY_SCAN_MCP_URL": "http://127.0.0.1:8000/mcp",
                "SECURITY_SCAN_MCP_AUTH_TOKEN": "",
                "SECURITY_MCP_AUTH_TOKEN": "",
            },
        ):
            result = security_scan_node(
                {
                    "messages": [("user", "Secret Scan 보안점검 실행해줘")],
                    "jwt_claims": {"user_id": "demo"},
                }
            )

        response = result["messages"][0].content
        self.assertIn("인증 토큰이 설정되어 있지 않아", response)
        self.assertIn("SECURITY_SCAN_MCP_AUTH_TOKEN", response)
        self.assertIn("서버를 재시작", response)

    def test_numbered_security_scan_menu_does_not_crash_without_mcp_token(self) -> None:
        config = self._config()
        with (
            patch.dict(
                "os.environ",
                {
                    "ENABLE_LLM_ROUTER": "true",
                    "SECURITY_SCAN_MCP_URL": "http://127.0.0.1:8000/mcp",
                    "SECURITY_SCAN_MCP_AUTH_TOKEN": "",
                    "SECURITY_MCP_AUTH_TOKEN": "",
                    "SECURITY_MCP_URL": "",
                },
            ),
            patch.object(llm_factory, "create_llm") as create_llm,
        ):
            create_llm.return_value.with_structured_output.return_value.invoke.return_value = (
                IntentClassification(category="feature_discovery")
            )
            menu = agent_app.invoke(
                {
                    "messages": [("user", "보안점검 어케해")],
                    "jwt_claims": {"user_id": "demo"},
                },
                config,
            )
            self.assertEqual(menu["intent_category"], "feature_discovery")
            self.assertIn("1. Secret Scan", menu["messages"][-1].content)

            selected = agent_app.invoke(
                {
                    "messages": [("user", "1")],
                    "jwt_claims": {"user_id": "demo"},
                },
                config,
            )

        self.assertIn("인증 토큰이 설정되어 있지 않아", selected["messages"][-1].content)
        self.assertEqual(create_llm.call_count, 1)

    def test_llm_router_is_enabled_by_default(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(llm_factory, "create_llm") as create_llm,
        ):
            create_llm.return_value.with_structured_output.return_value.invoke.return_value = (
                IntentClassification(category="package_download")
            )
            result = intent_classifier_node(
                {"messages": [("user", "사내에서 fastmcp 패키지 받는 방법이 뭐야?")]}
            )

        self.assertEqual(result["intent_category"], "package_download")
        create_llm.assert_called_once()

    def test_mcp_tools_expose_actionable_descriptions(self) -> None:
        self.assertIn("Queue", execute_sca_scan.description)
        self.assertIn("fixture", execute_sca_scan.description)
        schema = ScaScanInput.model_json_schema()
        self.assertTrue(schema["properties"]["user_id"]["description"])

    def test_mcp_client_uses_remote_tool_when_server_url_is_configured(self) -> None:
        with (
            patch.dict("os.environ", {"SECURITY_MCP_URL": "http://localhost:8000/mcp"}),
            patch.object(
                mcp_tools,
                "_call_remote_tool",
                return_value=[{"name": "repo-from-server"}],
            ) as remote_call,
        ):
            result = mcp_tools.query_external_repos.invoke(EmptyInput())

        self.assertEqual(result, [{"name": "repo-from-server"}])
        remote_call.assert_called_once_with("query_external_repos", {})

    def test_scan_product_listing_adapts_security_mcp_response(self) -> None:
        product_response = (
            '[{"system_id":"payments","service_id":"devops",'
            '"git_repo_url":"https://git.example.com/payments/api"}]'
        )
        with (
            patch.dict(
                "os.environ",
                {
                    "SECURITY_SCAN_MCP_URL": "http://localhost:8000/mcp",
                    "SECURITY_MCP_URL": "",
                },
            ),
            patch.object(
                mcp_tools,
                "_call_remote_tool",
                return_value=product_response,
            ) as remote_call,
        ):
            products = get_pg_product_list.invoke(ProductListInput(user_id="demo"))

        self.assertEqual(products[0]["system_id"], "payments")
        self.assertEqual(products[0]["service_id"], "devops")
        self.assertEqual(products[0]["product_id"], "https://git.example.com/payments/api")
        remote_call.assert_called_once_with(
            "get_my_products",
            {},
            server_url="http://localhost:8000/mcp",
            auth_token=None,
            fallback_on_unavailable=False,
        )

    def test_scan_request_maps_to_security_mcp_contract(self) -> None:
        response = '{"scan_id":"scan-123","status":"QUEUED"}'
        with (
            patch.dict(
                "os.environ",
                {"SECURITY_SCAN_MCP_URL": "http://localhost:8000/mcp"},
            ),
            patch.object(
                mcp_tools,
                "_call_remote_tool",
                return_value=response,
            ) as remote_call,
        ):
            result = execute_sca_scan.invoke(
                ScaScanInput(system_id="payments", service_id="devops")
            )

        self.assertEqual(result["scan_id"], "scan-123")
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["scan_type"], "SCA")
        remote_call.assert_called_once_with(
            "execute_sca_scan",
            {"system_id": "payments", "service_id": "devops"},
            server_url="http://localhost:8000/mcp",
            auth_token=None,
            fallback_on_unavailable=False,
        )

    def test_scan_results_map_server_payload_without_secret_values(self) -> None:
        response = (
            '{"system_id":"payments","service_id":"devops",'
            '"summary":{"total_detected":1,"severity_counts":{"high":1}},'
            '"detected_secrets":[{"rule":"aws-access-key","severity":"high",'
            '"file_path":"src/config.py","line_number":8,'
            '"detected_line":"[REDACTED]"}]}'
        )
        with (
            patch.dict(
                "os.environ",
                {"SECURITY_SCAN_MCP_URL": "http://localhost:8000/mcp"},
            ),
            patch.object(mcp_tools, "_call_remote_tool", return_value=response),
        ):
            result = get_secret_scan_result.invoke(
                {
                    "system_id": "payments",
                    "service_id": "devops",
                }
            )

        self.assertEqual(result["sc_output_result"], "success")
        self.assertEqual(result["findings"][0]["name"], "aws-access-key")
        self.assertEqual(result["findings"][0]["location"], "src/config.py")
        self.assertNotIn("detected_line", result["findings"][0])

    def test_scan_server_connection_error_does_not_return_fixture(self) -> None:
        with (
            patch.dict(
                "os.environ",
                {"SECURITY_SCAN_MCP_URL": "http://localhost:8000/mcp"},
            ),
            patch.object(
                mcp_tools,
                "_call_remote_tool",
                side_effect=RuntimeError("Unable to connect to Security MCP server"),
            ),
            self.assertRaisesRegex(RuntimeError, "Unable to connect"),
        ):
            execute_sca_scan.invoke(
                ScaScanInput(system_id="payments", service_id="devops")
            )

    def test_scan_node_runs_against_security_mcp_server_contract(self) -> None:
        calls = []

        def remote_tool(
            tool_name: str,
            arguments: dict[str, object],
            **kwargs: object,
        ) -> object:
            if tool_name == "get_accessible_product_groups":
                return mcp_tools._REMOTE_NOT_CONFIGURED
            calls.append((tool_name, arguments))
            if tool_name == "get_my_products":
                return (
                    '[{"system_id":"payments","service_id":"devops",'
                    '"git_repo_url":"https://git.example.com/payments/api"}]'
                )
            if tool_name == "execute_sca_scan":
                return '{"scan_id":"scan-123","status":"QUEUED"}'
            if tool_name == "get_sca_result":
                return (
                    '{"summary":{"vulnerable_components":1},'
                    '"vulnerable_components":[{"component_name":"lib-a",'
                    '"version":"1.0","max_severity":"HIGH",'
                    '"recommended_version":"1.2"}]}'
                )
            self.fail(f"Unexpected Security MCP tool: {tool_name}")

        config = self._config()
        with (
            patch.dict(
                "os.environ",
                {
                    "SECURITY_SCAN_MCP_URL": "http://localhost:8000/mcp",
                    "SECURITY_SCAN_MCP_AUTH_TOKEN": "test-token",
                    "SECURITY_MCP_URL": "",
                },
            ),
            patch.object(mcp_tools, "_call_remote_tool", side_effect=remote_tool),
        ):
            selection = agent_app.invoke(
                {
                    "messages": [("user", "payments SCA 점검해줘")],
                    "jwt_claims": {"user_id": "demo"},
                },
                config,
            )
            self.assertEqual(
                selection["__interrupt__"][0].value["type"],
                "scan_target_selection",
            )
            started = agent_app.invoke(Command(resume="1"), config)
            self.assertEqual(started["scan_id"], "scan-123")
            self.assertEqual(started["system_id"], "payments")
            self.assertEqual(started["service_id"], "devops")

            result = agent_app.invoke(
                {
                    "messages": [("user", "SCA 점검 결과 알려줘")],
                    "jwt_claims": {"user_id": "demo"},
                },
                config,
            )
            self.assertEqual(result["__interrupt__"][0].value["type"], "result_target")
            result = agent_app.invoke(Command(resume="1"), config)

        self.assertEqual(
            calls,
            [
                ("get_my_products", {}),
                ("get_my_products", {}),
                ("execute_sca_scan", {"system_id": "payments", "service_id": "devops"}),
                ("get_my_products", {}),
                ("get_my_products", {}),
                ("get_sca_result", {"system_id": "payments", "service_id": "devops"}),
            ],
        )
        self.assertIn("lib-a", result["messages"][-1].content)
        self.assertIn("1.2", result["messages"][-1].content)

    def test_mcp_tool_errors_do_not_fall_back_to_mock_data(self) -> None:
        with (
            patch.dict("os.environ", {"SECURITY_MCP_URL": "http://localhost:8000/mcp"}),
            patch.object(
                mcp_tools,
                "_call_remote_tool",
                side_effect=RuntimeError("MCP server unavailable"),
            ),
            self.assertRaisesRegex(RuntimeError, "MCP server unavailable"),
        ):
            mcp_tools.query_external_repos.invoke(EmptyInput())

    def test_mcp_connection_failure_falls_back_to_local_mock_tool(self) -> None:
        class UnavailableMcpClient:
            async def __aenter__(self) -> None:
                try:
                    raise httpx.ConnectError("connection refused")
                except httpx.ConnectError as cause:
                    raise RuntimeError(
                        f"Client failed to connect: {cause}"
                    ) from cause

            async def __aexit__(self, exc_type, exc_value, traceback) -> None:
                return None

        with (
            patch.dict("os.environ", {"SECURITY_MCP_URL": "http://localhost:8000/mcp"}),
            patch.object(mcp_tools, "Client", return_value=UnavailableMcpClient()),
            self.assertLogs("security_agent_v2.tools.mcp_tools", level="WARNING") as logs,
        ):
            repositories = mcp_tools.query_external_repos.invoke(EmptyInput())

        self.assertTrue(repositories)
        self.assertEqual(repositories[0]["name"], "company-pypi-proxy")
        self.assertIn("using local mock tool query_external_repos", logs.output[0])

    def test_unsupported_static_scan_and_ci_requests_are_not_scanned(self) -> None:
        self.assertEqual(
            _heuristic_route(
                "이 Python 코드에서 SQL Injection, XSS, 하드코딩된 Secret 탐지해 줘."
            ),
            "SupportGuide",
        )
        self.assertEqual(
            _heuristic_route("현재 빌드 파이프라인 상에서 보안 검사 통과했어?"),
            "SupportGuide",
        )
        self.assertEqual(
            _heuristic_route("이 PR(Pull Request) 자동 스캔 결과 알려줘."),
            "SupportGuide",
        )
        self.assertEqual(
            _heuristic_route("requirements.txt 의존성 패키지에 CVE 취약점이 있어?"),
            "SecurityScanAgent",
        )

    def test_support_guide_distinguishes_supported_sca_and_unsupported_sast(self) -> None:
        capability = agent_app.invoke(
            {
                "messages": [("user", "너는 무슨 일을 할 수 있어?")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )
        self.assertNotIn("입력 방법 및 한계", capability["messages"][-1].content)
        self.assertNotIn("현재 미지원", capability["messages"][-1].content)

        static_scan = agent_app.invoke(
            {
                "messages": [("user", "이 코드에서 SQL Injection 점검해줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )
        self.assertIn("현재 미지원", static_scan["messages"][-1].content)
        self.assertIn("자동 스캔", static_scan["messages"][-1].content)

        pipeline_status = agent_app.invoke(
            {
                "messages": [
                    ("user", "현재 빌드 파이프라인 상에서 보안 검사 통과했어?")
                ],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )
        self.assertIn("현재 연동되어 있지 않습니다", pipeline_status["messages"][-1].content)
        self.assertIn("통과했는지 확인했다고 답변할 수 없습니다", pipeline_status["messages"][-1].content)

    def test_remediation_without_existing_report_does_not_trigger_new_scan(self) -> None:
        result = agent_app.invoke(
            {
                "messages": [("user", "가장 위험한 취약점 조치 순서 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )

        self.assertIn("스캔 결과가 없어", result["messages"][-1].content)
        self.assertIsNone(result.get("scan_task_ids"))

    def test_scan_report_formats_verified_details_and_orders_severity(self) -> None:
        report = _format_findings_report(
            {
                "target_id": "pay-api-v1",
                "scan_type": "SCA",
                "summary": "취약점 2건",
                "findings": [
                    {
                        "severity": "medium",
                        "name": "CVE-2025-2000",
                        "package_name": "other-lib",
                        "cvss_score": 5.1,
                    },
                    {
                        "severity": "critical",
                        "name": "CVE-2025-1000",
                        "package_name": "payment-lib",
                        "ecosystem": "pypi",
                        "current_version": "1.0",
                        "fixed_version": "1.2",
                        "cwe_id": "CWE-89",
                    },
                ],
            }
        )

        self.assertLess(report.index("CVE-2025-1000"), report.index("CVE-2025-2000"))
        self.assertIn("🔴 Critical", report)
        self.assertIn("CWE-89", report)
        self.assertIn("수정 버전: `1.2`", report)
        self.assertIn("payment-lib==1.2", report)
        self.assertIn("수정 코드가 결과에 포함되지 않은", report)

    def test_remediation_uses_existing_report_without_starting_new_scan(self) -> None:
        result = agent_app.invoke(
            {
                "messages": [("user", "가장 위험한 항목부터 수정 순서 정리해줘")],
                "jwt_claims": {"user_id": "demo"},
                "actionable_report": {
                    "scan_type": "SCA",
                    "results": [
                        {
                            "target_id": "pay-api-v1",
                            "scan_type": "SCA",
                            "sc_output_result": "success",
                            "summary": "취약점 1건",
                            "findings": [
                                {
                                    "severity": "high",
                                    "name": "CVE-2025-9999",
                                    "package_name": "affected-lib",
                                    "fixed_version": "4.2.0",
                                }
                            ],
                        }
                    ],
                },
            },
            self._config(),
        )

        message = result["messages"][-1].content
        self.assertIn("CVE-2025-9999", message)
        self.assertIn("4.2.0", message)
        self.assertEqual(result["actionable_report"]["results"][0]["target_id"], "pay-api-v1")

    def test_domain_keyword_lists_related_features(self) -> None:
        result = agent_app.invoke(
            {
                "messages": [("user", "외부저장소")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )
        message = result["messages"][-1].content
        self.assertIn("기능을 사용할 수 있습니다", message)
        self.assertIn("외부 저장소 목록 조회", message)
        self.assertIn("패키지 다운로드", message)

    def test_feature_number_selection_expands_to_feature_request(self) -> None:
        config = self._config()
        menu = agent_app.invoke(
            {
                "messages": [("user", "외부저장소")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )
        self.assertIsNotNone(menu.get("pending_feature_options"))

        selected = agent_app.invoke(
            {"messages": [("user", "1")], "jwt_claims": {"user_id": "demo"}},
            config,
        )
        self.assertIn("외부 연동 저장소 목록", selected["messages"][-1].content)
        self.assertIsNone(selected.get("pending_feature_options"))

    def test_unknown_intent_returns_clarification_message(self) -> None:
        result = agent_app.invoke(
            {
                "messages": [("user", "오늘 기분이 어때?")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )

        self.assertIn("이해하지 못했습니다", result["messages"][-1].content)

    def test_cli_ctrl_c_exits_without_traceback(self) -> None:
        output = StringIO()
        with patch("builtins.input", side_effect=KeyboardInterrupt), redirect_stdout(output):
            cli_main()

        self.assertIn("대화를 종료합니다.", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_invalid_target_selection_repeats_selection(self) -> None:
        config = self._config()
        initial = agent_app.invoke(
            {"messages": [("user", "SCA scan")], "jwt_claims": {"user_id": "demo"}},
            config,
        )
        self.assertEqual(initial["__interrupt__"][0].value["type"], "scan_target_selection")
        selection_message = initial["__interrupt__"][0].value["message"]
        self.assertIn("System ID", selection_message)
        self.assertIn("Repository", selection_message)

        retry = agent_app.invoke(Command(resume="99"), config)
        self.assertEqual(
            retry["__interrupt__"][0].value["type"], "scan_target_selection"
        )

        completed = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(completed["scan_status"], "awaiting_result")
        self.assertIsNone(completed["actionable_report"])

    def test_scan_result_is_requested_separately(self) -> None:
        config, started = self._start_scan_and_select_package()

        self.assertEqual(started["scan_status"], "awaiting_result")
        self.assertIsNone(started["actionable_report"])
        self.assertIn("SCA", started["scan_task_ids"])

        result = agent_app.invoke(
            {
                "messages": [("user", "SCA scan result 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )
        self.assertEqual(result["__interrupt__"][0].value["type"], "result_target")
        result = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(result["scan_status"], "progressing")
        self.assertEqual(result["actionable_report"]["results"][0]["scan_type"], "SCA")
        self.assertIn("아직 진행 중", result["messages"][-1].content)

    def test_existing_sca_result_can_be_queried_without_prior_scan_in_thread(self) -> None:
        config = self._config()
        target_prompt = agent_app.invoke(
            {
                "messages": [("user", "SCA 결과 보여줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        self.assertIsNone(target_prompt.get("scan_status"))
        self.assertEqual(target_prompt["__interrupt__"][0].value["type"], "result_target")

        result = agent_app.invoke(Command(resume="2"), config)

        self.assertEqual(result["scan_status"], "success")
        self.assertEqual(result["system_id"], "payments")
        self.assertEqual(result["service_id"], "devops")
        self.assertIn("pay-api-v1", result["messages"][-1].content)

    def test_result_target_is_selected_again_instead_of_reusing_previous_scan(self) -> None:
        config, _ = self._start_scan_and_select_package()
        target_prompt = agent_app.invoke(
            {
                "messages": [("user", "SCA 결과 보여줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        self.assertEqual(target_prompt["__interrupt__"][0].value["type"], "result_target")
        result = agent_app.invoke(Command(resume="2"), config)

        self.assertEqual(result["scan_status"], "success")
        self.assertEqual(result["service_id"], "devops")
        self.assertIn("pay-api-v1", result["messages"][-1].content)

    def test_scan_output_status_controls_result_message(self) -> None:
        progressing = {"sc_output_result": "progressing"}
        success = {"sc_output_result": "success", "summary": "점검 결과입니다."}
        failure = {"sc_output_result": "failure", "failure_reason": "스캔 서버 오류"}

        self.assertIn("아직 진행 중", _scan_result_message(progressing))
        self.assertEqual(_scan_result_message(success), "점검 결과입니다.")
        self.assertIn("스캔 서버 오류", _scan_result_message(failure))
        self.assertEqual(_aggregate_scan_status([progressing, success]), "progressing")
        self.assertEqual(_aggregate_scan_status([failure, success]), "failure")
        self.assertEqual(_aggregate_scan_status([success]), "success")

    def test_mock_scan_results_include_each_output_status(self) -> None:
        progressing = get_sca_scan_result.invoke(
            {"target_id": "payment-pkg"}
        )
        success = get_sca_scan_result.invoke({"target_id": "pay-api-v1"})
        failure = get_secret_scan_result.invoke({"target_id": "pay-api-v1"})

        self.assertEqual(progressing["sc_output_result"], "progressing")
        self.assertEqual(success["sc_output_result"], "success")
        self.assertEqual(failure["sc_output_result"], "failure")
        self.assertTrue(failure["failure_reason"])

    def test_explicit_secret_result_uses_secret_result_tool(self) -> None:
        config, _ = self._start_scan_and_select_package()

        result = agent_app.invoke(
            {
                "messages": [("user", "secret scan 보안점검 결과 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )
        self.assertEqual(result["__interrupt__"][0].value["type"], "result_target")
        result = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(result["actionable_report"]["results"][0]["scan_type"], "SECRET")

    def test_korean_sensitive_information_result_uses_secret_tool(self) -> None:
        config, _ = self._start_scan_and_select_package()

        result = agent_app.invoke(
            {
                "messages": [("user", "민감정보 점검 결과 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )
        self.assertEqual(result["__interrupt__"][0].value["type"], "result_target")
        result = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(result["actionable_report"]["results"][0]["scan_type"], "SECRET")

    def test_ambiguous_result_asks_type_then_target(self) -> None:
        config, _ = self._start_scan_and_select_package()
        ambiguous = agent_app.invoke(
            {
                "messages": [("user", "점검 결과 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )
        self.assertEqual(ambiguous["__interrupt__"][0].value["type"], "result_scan_type")

        target_prompt = agent_app.invoke(Command(resume="2"), config)
        self.assertEqual(target_prompt["__interrupt__"][0].value["type"], "result_target")
        target_prompt = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(target_prompt["scan_status"], "progressing")
        self.assertEqual(
            target_prompt["actionable_report"]["results"][0]["scan_type"], "SCA"
        )

    def test_sca_result_menu_selection_handles_korean_number_suffix(self) -> None:
        config, _ = self._start_scan_and_select_package()
        agent_app.invoke(
            {
                "messages": [("user", "점검 결과 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        result = agent_app.invoke(Command(resume="2번"), config)

        self.assertEqual(result["__interrupt__"][0].value["type"], "result_target")
        result = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(result["actionable_report"]["results"][0]["scan_type"], "SCA")

    def test_missing_remote_scan_result_is_reported_without_generic_ui_error(self) -> None:
        config, _ = self._start_scan_and_select_package()
        agent_app.invoke(
            {
                "messages": [("user", "점검 결과 알려줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        missing_result_tool = Mock(
            invoke=Mock(
                side_effect=ScanMCPToolError(
                    "get_sca_result", "No matching SCA result was found"
                )
            )
        )
        with patch(
            "security_agent_v2.nodes.security_scan_node.get_sca_scan_result",
            new=missing_result_tool,
        ):
            target_prompt = agent_app.invoke(Command(resume="2"), config)
            self.assertEqual(
                target_prompt["__interrupt__"][0].value["type"], "result_target"
            )
            result = agent_app.invoke(Command(resume="1"), config)

        self.assertIn("아직 찾지 못했습니다", result["messages"][-1].content)
        self.assertIn("다시 조회해주세요", result["messages"][-1].content)

    def test_misspelled_result_followup_does_not_start_another_scan(self) -> None:
        config, _ = self._start_scan_and_select_package("SCA scan")

        result = agent_app.invoke(
            {
                "messages": [("user", "겨로가 보여줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            config,
        )

        self.assertEqual(result["intent_category"], "scan_result")
        self.assertEqual(result["__interrupt__"][0].value["type"], "result_scan_type")

        target_prompt = agent_app.invoke(Command(resume="2"), config)
        self.assertEqual(target_prompt["__interrupt__"][0].value["type"], "result_target")
        completed = agent_app.invoke(Command(resume="1"), config)
        self.assertEqual(completed["scan_status"], "progressing")
        self.assertIn("아직 진행 중", completed["messages"][-1].content)

    def test_ambiguous_result_typo_without_scan_context_asks_before_scanning(self) -> None:
        result = agent_app.invoke(
            {
                "messages": [("user", "겨로가 보여줘")],
                "jwt_claims": {"user_id": "demo"},
            },
            self._config(),
        )

        self.assertEqual(result["intent_category"], "unknown")
        self.assertIn("결과를 조회하시려는 건가요", result["messages"][-1].content)
        self.assertIn("확인 없이 새 점검을 실행하지 않았습니다", result["messages"][-1].content)


if __name__ == "__main__":
    unittest.main()
