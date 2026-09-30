"""MCP tool contracts and the local implementation used by the agent.

The tool names and Pydantic input models are the stable agent contract.
Security scan operations adapt to the dedicated Security MCP server when
SECURITY_SCAN_MCP_URL is set; otherwise local fixtures remain available.
"""

import asyncio
import json
import logging
import os
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError as FastMCPToolError
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from security_agent_v2.mcp_auth import get_request_mcp_auth_token


_REMOTE_NOT_CONFIGURED = object()
logger = logging.getLogger(__name__)


class ScanMCPToolError(RuntimeError):
    """A dedicated scan MCP call failed without leaking server details to users."""

    def __init__(self, tool_name: str, details: str = "") -> None:
        message = f"Security MCP tool {tool_name!r} failed"
        if details:
            message = f"{message}: {details}"
        super().__init__(message)
        self.tool_name = tool_name
        self.details = details

    @property
    def result_not_found(self) -> bool:
        details = self.details.casefold()
        return "not found" in details or "no matching" in details


def _has_transport_error(error: BaseException) -> bool:
    pending = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, httpx.TransportError):
            return True
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
    return False


def _call_remote_tool(
    tool_name: str,
    arguments: dict[str, object],
    *,
    server_url: str | None = None,
    auth_token: str | None = None,
    fallback_on_unavailable: bool = True,
) -> Any:
    server_url = (server_url or os.getenv("SECURITY_MCP_URL", "")).strip()
    if not server_url:
        return _REMOTE_NOT_CONFIGURED

    headers = {}
    token = auth_token or os.getenv("SECURITY_MCP_AUTH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async def call() -> object:
        transport = StreamableHttpTransport(server_url, headers=headers or None)
        try:
            async with Client(transport) as client:
                result = await client.call_tool(tool_name, arguments)
        except httpx.TransportError as error:
            if not fallback_on_unavailable:
                raise RuntimeError(
                    f"Unable to connect to Security MCP server at {server_url}"
                ) from error
            logger.warning(
                "Security MCP server unavailable; using local mock tool %s: %s",
                tool_name,
                error,
            )
            return _REMOTE_NOT_CONFIGURED
        except RuntimeError as error:
            if not _has_transport_error(error):
                raise
            if not fallback_on_unavailable:
                raise RuntimeError(
                    f"Unable to connect to Security MCP server at {server_url}"
                ) from error
            logger.warning(
                "Security MCP server unavailable; using local mock tool %s: %s",
                tool_name,
                error,
            )
            return _REMOTE_NOT_CONFIGURED
        if result.is_error:
            details = "; ".join(
                item.text for item in result.content if hasattr(item, "text")
            )
            raise ScanMCPToolError(tool_name, details)
        structured = result.structured_content
        if isinstance(structured, dict) and "result" in structured:
            return structured["result"]
        if structured is not None:
            return structured
        if len(result.content) == 1 and hasattr(result.content[0], "text"):
            return result.content[0].text
        return result.content

    return asyncio.run(call())


def _call_scan_server_tool(tool_name: str, arguments: dict[str, object]) -> Any:
    """Call the dedicated Security MCP server without masking outages as mock results."""
    server_url = os.getenv("SECURITY_SCAN_MCP_URL", "").strip()
    if not server_url:
        return _REMOTE_NOT_CONFIGURED
    try:
        return _call_remote_tool(
            tool_name,
            arguments,
            server_url=server_url,
            auth_token=(
                get_request_mcp_auth_token()
                or os.getenv("SECURITY_SCAN_MCP_AUTH_TOKEN")
                or os.getenv("SECURITY_MCP_AUTH_TOKEN")
            ),
            fallback_on_unavailable=False,
        )
    except ScanMCPToolError:
        raise
    except FastMCPToolError as error:
        raise ScanMCPToolError(tool_name, str(error)) from error
    except RuntimeError as error:
        raise ScanMCPToolError(tool_name, str(error)) from error


def _decode_json_response(response: Any, expected_type: type) -> Any:
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except json.JSONDecodeError as error:
            raise RuntimeError("Security MCP returned invalid JSON") from error
    if not isinstance(response, expected_type):
        raise RuntimeError(
            f"Security MCP returned {type(response).__name__}; "
            f"expected {expected_type.__name__}"
        )
    return response


def _scan_result_from_server(
    response: Any, target_id: str, scan_type: str
) -> dict[str, Any]:
    payload = _decode_json_response(response, dict)
    if scan_type == "SCA":
        components = payload.get("vulnerable_components")
        if not isinstance(components, list):
            raise RuntimeError("Security MCP returned invalid SCA components")
        if any(not isinstance(component, dict) for component in components):
            raise RuntimeError("Security MCP returned an invalid SCA component")
        findings = [
            {
                "severity": component.get("max_severity", "unknown"),
                "name": component.get("component_name", "Unknown component"),
                "package_name": component.get("component_name", "Unknown component"),
                "current_version": component.get("version"),
                "fixed_version": component.get("recommended_version"),
                "dependency_type": component.get("dependency_type"),
            }
            for component in components
        ]
        summary = payload.get("summary", {})
        summary_text = (
            "; ".join(f"{key}: {value}" for key, value in summary.items())
            if isinstance(summary, dict)
            else str(summary)
        )
    else:
        detected = payload.get("detected_secrets")
        if not isinstance(detected, list):
            raise RuntimeError("Security MCP returned invalid Secret findings")
        if any(not isinstance(item, dict) for item in detected):
            raise RuntimeError("Security MCP returned an invalid Secret finding")
        findings = [
            {
                "severity": item.get("severity", "unknown"),
                "name": item.get("rule", "Potential secret detected"),
                "location": item.get("file_path", "Unknown file"),
                "line": item.get("line_number"),
            }
            for item in detected
        ]
        summary = payload.get("summary", {})
        if isinstance(summary, dict):
            counts = summary.get("severity_counts", {})
            summary_text = (
                f"총 {summary.get('total_detected', len(findings))}건 탐지"
                + (
                    f" (위험도별: {', '.join(f'{key} {value}건' for key, value in counts.items())})"
                    if isinstance(counts, dict) and counts
                    else ""
                )
            )
        else:
            summary_text = str(summary)
    return {
        "target_id": target_id,
        "scan_type": scan_type,
        "sc_output_result": "success",
        "summary": summary_text or f"{scan_type} 점검 결과를 조회했습니다.",
        "findings": findings,
    }


class UserIdInput(BaseModel):
    user_id: str | None = Field(
        default=None,
        description="인증된 사용자의 내부 ID. 백엔드 권한 조회에 사용하며 사용자가 입력한 임의 ID를 신뢰하면 안 됩니다.",
    )


class ProductListInput(BaseModel):
    user_id: str = Field(description="인증된 사용자 ID. 사용자가 조회 권한이 있는 scan 대상만 반환합니다.")


class EmptyInput(BaseModel):
    pass


class ApprovalLineInput(BaseModel):
    repo_type: str = Field(description="생성할 저장소 유형: internal 또는 external.")
    product_group: str | None = Field(
        default=None,
        description="Internal Repo의 Product Group ID. External Proxy Repo이면 null일 수 있습니다.",
    )


class ExternalRepoNameInput(BaseModel):
    external_proxy_url: str = Field(description="외부에서 연동할 저장소의 http 또는 https URL.")


class RepoCreationInput(BaseModel):
    repo_data: dict[str, object] = Field(
        description="저장소 이름, 유형, Product Group 및 외부 원본 URL을 포함하는 저장소 요청 데이터."
    )
    approval_line: list[dict[str, object]] = Field(
        description="사용자에게 제시하고 명시적 승인을 받은 결재자 순서와 역할."
    )


class PackageNameInput(BaseModel):
    package_name: str = Field(description="등록하려는 패키지 이름.")
    repo_name: str = Field(description="패키지를 등록할 상위 내부 저장소 이름.")


class PackageBaselineInput(BaseModel):
    package_data: dict[str, object] = Field(
        description="Repo, 패키지명, 빌드 도구/버전, Git URL/브랜치, manifest 경로를 포함한 SDEP baseline."
    )


class PackageInput(BaseModel):
    package_name: str = Field(description="SDEP에 이미 등록되어 빌드할 패키지 이름.")


class AccessibleTargetsInput(UserIdInput):
    keyword: str | None = Field(
        default=None,
        description="대상 이름/키워드 필터. 생략하면 권한 대상 전체를 조회합니다.",
    )


class TriggerSecurityScanInput(BaseModel):
    target_id: str = Field(description="권한 확인된 패키지 또는 애플리케이션의 backend ID.")
    target_type: str = Field(description="스캔 대상 유형: package 또는 application.")
    scan_type: str = Field(description="실행할 스캔 유형: SCA, SECRET 또는 ALL.")


class ScanResultInput(BaseModel):
    system_id: str | None = Field(
        default=None,
        description="get_my_products가 반환한 시스템 ID.",
    )
    service_id: str | None = Field(
        default=None,
        description="get_my_products가 반환한 서비스 ID.",
    )
    target_id: str | None = Field(
        default=None,
        description="로컬 fixture 호환용 대상 ID.",
    )
    user_id: str | None = Field(
        default=None,
        description="인증된 요청 사용자 ID. 원격 MCP 호출 시 대상 권한 검증에 필요합니다.",
    )


class RepoIntegrationInput(BaseModel):
    package_name: str = Field(description="외부 저장소에서 조회하려는 패키지 이름.")
    ext_url: str = Field(description="패키지가 제공되는 외부 저장소의 URL.")


class SecretScanInput(BaseModel):
    system_id: str = Field(description="대상 소속 Product Group/System ID.")
    service_id: str = Field(description="대상 백엔드 서비스 ID. 패키지는 보통 sdep입니다.")
    target_type: str | None = Field(default=None, description="로컬 fixture 호환용 대상 유형.")
    target_name: str | None = Field(default=None, description="로컬 fixture 호환용 대상 이름.")
    user_id: str | None = Field(default=None, description="로컬 fixture 호환용 사용자 ID.")


class ScaScanInput(SecretScanInput):
    pass


class SbomExtractionInput(BaseModel):
    scan_id: str = Field(description="완료된 보안 스캔의 ID. 비동기 SBOM 추출 작업을 연결합니다.")


@tool(args_schema=UserIdInput)
def get_accessible_product_groups(user_id: str | None) -> list[dict]:
    """List Product Groups the authenticated user may access.

    Use this before selecting an internal repository group. The result contains
    Product Group IDs and display names; an empty result means no groups are
    available. This local implementation returns development fixtures.
    """
    remote = _call_remote_tool(
        "get_accessible_product_groups", {"user_id": user_id}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    if not user_id:
        return []
    return [
        {"id": "payments", "name": "Payments", "user_ids": ["test_user_01", "demo"]},
        {"id": "platform", "name": "Platform Engineering", "user_ids": ["test_user_01"]},
    ]


@tool(args_schema=ProductListInput)
def get_pg_product_list(user_id: str) -> list[dict]:
    """List authorized security-scan targets grouped by system and service.

    Each returned row identifies a system_id and service_id. When connected to
    Security MCP, rows are derived from get_my_products and include the repository
    URL returned by that server. Use the exact IDs for scan requests and results.
    """
    scan_products = _call_scan_server_tool("get_my_products", {})
    if scan_products is not _REMOTE_NOT_CONFIGURED:
        rows = _decode_json_response(scan_products, list)
        normalized = []
        for row in rows:
            if not isinstance(row, dict) or not all(
                isinstance(row.get(field), str) and row[field]
                for field in ("system_id", "service_id", "git_repo_url")
            ):
                raise RuntimeError("Security MCP returned an invalid product record")
            repository = row["git_repo_url"]
            normalized.append(
                {
                    "system_id": row["system_id"],
                    "system_name": row["system_id"],
                    "service_id": row["service_id"],
                    "platform": row["service_id"],
                    "package_name": repository,
                    "product_id": repository,
                    "git_repo_url": repository,
                }
            )
        return normalized

    remote = _call_remote_tool("get_pg_product_list", {"user_id": user_id})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    if user_id not in {"test_user_01", "demo"}:
        return []
    return [
        {
            "system_id": "payments",
            "system_name": "Payments",
            "service_id": "sdep",
            "platform": "sdep",
            "package_name": "payment-pkg",
        },
        {
            "system_id": "payments",
            "system_name": "Payments",
            "service_id": "devops",
            "platform": "devops",
            "product_id": "pay-api-v1",
        },
    ]


@tool(args_schema=ApprovalLineInput)
def get_approval_line(repo_type: str, product_group: str | None) -> list[dict]:
    """Fetch the ordered approval line required to create an internal or external repository.

    Supply the repository type and, for internal repositories, the Product Group.
    Show the returned approvers to the user and obtain explicit confirmation
    before calling request_repo_creation. This local implementation returns fixtures.
    """
    remote = _call_remote_tool(
        "get_approval_line",
        {"repo_type": repo_type, "product_group": product_group},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return [
        {"step": 1, "role": "Product Owner", "name": "Product Owner", "group": product_group},
        {"step": 2, "role": "Security Team", "name": "Security Team", "group": product_group},
    ]


@tool(args_schema=EmptyInput)
def query_external_repos() -> list[dict]:
    """List integrated external proxy repositories available across Product Groups.

    Each result provides repository name, upstream URL, package format, type and
    status. Use for external proxy inventory and package ecosystem lookup.
    This local implementation returns development fixtures.
    """
    remote = _call_remote_tool("query_external_repos", {})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return [
        {
            "name": "company-pypi-proxy",
            "url": "https://nexus.example.com/repository/company-pypi-proxy/simple/",
            "format": "pypi",
            "repo_type": "external_proxy",
            "status": "integrated",
        },
        {
            "name": "company-maven-proxy",
            "url": "https://nexus.example.com/repository/company-maven-proxy/",
            "format": "maven",
            "repo_type": "external_proxy",
            "status": "integrated",
        },
        {
            "name": "company-npm-proxy",
            "url": "https://nexus.example.com/repository/company-npm-proxy/",
            "format": "npm",
            "repo_type": "external_proxy",
            "status": "integrated",
        },
    ]


@tool(args_schema=EmptyInput)
def query_integrated_repos() -> list[dict]:
    """List repositories integrated with the company platform.

    Results include internal hosted and integrated proxy repositories with
    their URL, format, type, Product Group (when applicable) and status.
    This local implementation returns development fixtures.
    """
    remote = _call_remote_tool("query_integrated_repos", {})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return [
        {
            "name": "payments-repo",
            "url": "https://git.example.com/payments/payments-repo",
            "format": "git",
            "repo_type": "internal_hosted",
            "product_group": "payments",
            "status": "integrated",
        },
        {
            "name": "company-maven-proxy",
            "url": "https://nexus.example.com/repository/company-maven-proxy/",
            "format": "maven",
            "repo_type": "external_proxy",
            "status": "integrated",
        },
        {
            "name": "company-npm-proxy",
            "url": "https://nexus.example.com/repository/company-npm-proxy/",
            "format": "npm",
            "repo_type": "external_proxy",
            "status": "integrated",
        },
    ]


@tool(args_schema=ExternalRepoNameInput)
def name_external_repo(external_proxy_url: str) -> dict:
    """Validate an external http(s) repository URL and derive its backend repository name.

    This helper does not create or approve the repository. Its validated name
    and source URL are inputs to the later approval request.
    """
    remote = _call_remote_tool(
        "name_external_repo", {"external_proxy_url": external_proxy_url}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    parsed = urlparse(external_proxy_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"valid": False, "error": "Invalid URL"}

    path_name = parsed.path.rstrip("/").split("/")[-1]
    host_name = parsed.hostname.replace(".", "-") if parsed.hostname else "external"
    repo_name = path_name or host_name
    return {
        "valid": True,
        "repo_name": repo_name.casefold(),
        "source_url": external_proxy_url.strip(),
    }


@tool(args_schema=RepoCreationInput)
def request_repo_creation(repo_data: dict, approval_line: list[dict]) -> dict:
    """Submit a repository creation approval ticket after explicit user consent.

    Provide the complete repository data and the approval line already shown to
    and accepted by the user. Returns a ticket ID; it does not mean the repository
    has been provisioned. This local implementation creates a fixture ticket.
    """
    remote = _call_remote_tool(
        "request_repo_creation",
        {"repo_data": repo_data, "approval_line": approval_line},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return {"status": "submitted", "ticket_id": f"REQ-{uuid4().hex[:8].upper()}", "repo": repo_data, "approval_line": approval_line}


@tool(args_schema=PackageNameInput)
def validate_package_name(package_name: str, repo_name: str) -> dict:
    """Check whether a package name is available within its target repository.

    Call before creating a package baseline. A false valid field means the
    name conflicts within that repository. This local implementation uses fixtures.
    """
    remote = _call_remote_tool(
        "validate_package_name",
        {"package_name": package_name, "repo_name": repo_name},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    duplicates = {("payments-repo", "payment-pkg"), ("platform-repo", "platform-core")}
    if (repo_name.casefold(), package_name.casefold()) in duplicates:
        return {"valid": False, "error": "Duplicate Name", "message": "Package name already exists."}
    return {"valid": True}


@tool(args_schema=PackageBaselineInput)
def create_package_baseline(package_data: dict) -> dict:
    """Register an SDEP package baseline from complete repository/build/source metadata.

    package_data should include repo_name, package_name, build_tool,
    build_tool_version, git_url, git_branch and manifest_path. Returns a package
    ID. This local implementation returns a fixture response.
    """
    remote = _call_remote_tool(
        "create_package_baseline", {"package_data": package_data}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return {"status": "created", "package_id": f"PKG-{uuid4().hex[:8].upper()}", **package_data}


@tool(args_schema=PackageInput)
def trigger_build(package_name: str) -> dict:
    """Queue a build for an existing SDEP package.

    The package name is sufficient because SDEP owns the saved Git/build
    metadata. Returns a build ID and queued status, not build output.
    This local implementation returns a fixture response.
    """
    remote = _call_remote_tool("trigger_build", {"package_name": package_name})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return {"status": "queued", "package_name": package_name, "build_id": f"BUILD-{uuid4().hex[:8].upper()}"}


@tool(args_schema=UserIdInput)
def get_accessible_packages(user_id: str | None) -> list[str]:
    """List package names visible to an authenticated user.

    Use for permission checks before package-specific security operations.
    This local implementation returns development fixtures.
    """
    remote = _call_remote_tool("get_accessible_packages", {"user_id": user_id})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return ["payment-pkg", "platform-core", "demo-pkg"] if user_id else []


@tool(args_schema=UserIdInput)
def get_accessible_products(user_id: str | None) -> list[str]:
    """List external DevOps product identifiers visible to an authenticated user.

    Use for permission checks before product-specific security operations.
    This local implementation returns development fixtures.
    """
    remote = _call_remote_tool("get_accessible_products", {"user_id": user_id})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return ["payments-service", "checkout-service"] if user_id else []


@tool(args_schema=AccessibleTargetsInput)
def get_accessible_targets(user_id: str | None, keyword: str | None = None) -> list[dict]:
    """List authorized application and package targets, optionally matching a keyword.

    Results include a target ID, display name, target type and aliases. An empty
    result means no matching accessible target exists. This local implementation
    returns development fixtures.
    """
    remote = _call_remote_tool(
        "get_accessible_targets", {"user_id": user_id, "keyword": keyword}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    targets = [
        {"id": "pay-api-v1", "name": "결제 API", "target_type": "application", "keywords": ["결제", "payment"]},
        {"id": "pay-batch", "name": "결제 배치", "target_type": "application", "keywords": ["결제", "payment"]},
        {"id": "payment-pkg", "name": "payment-pkg", "target_type": "package", "keywords": ["결제", "payment"]},
        {"id": "platform-core", "name": "platform-core", "target_type": "package", "keywords": ["플랫폼", "platform"]},
    ]
    if not user_id:
        return []
    if not keyword:
        return targets
    lowered = keyword.casefold()
    return [
        target for target in targets
        if lowered in target["name"].casefold()
        or any(lowered in value.casefold() for value in target["keywords"])
    ]


@tool(args_schema=TriggerSecurityScanInput)
def trigger_security_scan(target_id: str, target_type: str, scan_type: str) -> dict:
    """Start an asynchronous generic security scan for a confirmed target.

    Returns a task ID and started status. It does not return findings or a
    completion result. This local implementation returns a fixture task.
    """
    remote = _call_remote_tool(
        "trigger_security_scan",
        {
            "target_id": target_id,
            "target_type": target_type,
            "scan_type": scan_type,
        },
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return {
        "status": "started",
        "task_id": f"TASK-{uuid4().hex[:8].upper()}",
        "target_id": target_id,
        "target_type": target_type,
        "scan_type": scan_type,
    }


@tool(args_schema=UserIdInput)
def get_all_scanned_targets(user_id: str | None) -> list[dict]:
    """List accessible targets that have security-scan history.

    Each row includes supported scan types. Use this to select a permitted
    target before querying a result. This local implementation returns fixtures.
    """
    remote = _call_remote_tool("get_all_scanned_targets", {"user_id": user_id})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    if not user_id:
        return []
    return [
        {"id": "pay-api-v1", "name": "pay-api-v1", "target_type": "application", "scan_types": ["SCA", "SECRET"]},
        {"id": "payment-pkg", "name": "payment-pkg", "target_type": "package", "scan_types": ["SCA"]},
    ]


_MOCK_SCAN_RESULTS = {
    ("payment-pkg", "SCA"): {
        "sc_output_result": "progressing",
        "status": "in_progress",
        "failure_reason": None,
        "summary": "payment-pkg SCA 점검이 아직 진행 중입니다.",
        "findings": [],
    },
    ("pay-api-v1", "SCA"): {
        "sc_output_result": "success",
        "status": "completed",
        "failure_reason": None,
        "summary": "pay-api-v1 SCA 점검 결과: 조치가 필요한 항목 1건",
        "findings": [{"severity": "high", "message": "취약한 의존성을 업데이트해야 합니다."}],
    },
    ("pay-api-v1", "SECRET"): {
        "sc_output_result": "failure",
        "status": "failed",
        "failure_reason": "스캔 대상 저장소에 일시적으로 접근할 수 없습니다.",
        "summary": None,
        "findings": [],
    },
}


def _get_scan_result(target_id: str, scan_type: str) -> dict:
    result = _MOCK_SCAN_RESULTS.get(
        (target_id.casefold(), scan_type),
        {
            "sc_output_result": "success",
            "status": "completed",
            "failure_reason": None,
            "summary": f"{target_id} {scan_type} 점검 결과: 조치가 필요한 항목 1건",
            "findings": [{"severity": "high", "message": "검토가 필요한 보안 항목이 있습니다."}],
        },
    )
    return {"target_id": target_id, "scan_type": scan_type, **result}


@tool(args_schema=ScanResultInput)
def get_secret_scan_result(
    system_id: str | None = None,
    service_id: str | None = None,
    target_id: str | None = None,
    user_id: str | None = None,
) -> dict:
    """Fetch the latest Secret scan result for a selected authorized system/service.

    The connected Security MCP server returns a sanitized JSON report. Secret
    values are never included in the agent-facing findings.
    """
    if os.getenv("SECURITY_SCAN_MCP_URL", "").strip() and (
        not system_id or not service_id
    ):
        raise ValueError("system_id and service_id are required for scan results")
    remote = _call_scan_server_tool(
        "get_secret_scan_result",
        {"system_id": system_id, "service_id": service_id},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return _scan_result_from_server(
            remote, f"{system_id}/{service_id}", "SECRET"
        )
    remote = _call_remote_tool(
        "get_secret_scan_result", {"target_id": target_id, "user_id": user_id}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    if not target_id:
        raise ValueError("target_id is required when using local scan fixtures")
    return _get_scan_result(target_id, "SECRET")


@tool(args_schema=ScanResultInput)
def get_sca_scan_result(
    system_id: str | None = None,
    service_id: str | None = None,
    target_id: str | None = None,
    user_id: str | None = None,
) -> dict:
    """Fetch the latest SCA result for a selected authorized system/service.

    The connected Security MCP server returns a JSON summary and vulnerable
    components, which this adapter normalizes for the scan report.
    """
    if os.getenv("SECURITY_SCAN_MCP_URL", "").strip() and (
        not system_id or not service_id
    ):
        raise ValueError("system_id and service_id are required for scan results")
    remote = _call_scan_server_tool(
        "get_sca_result",
        {"system_id": system_id, "service_id": service_id},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return _scan_result_from_server(
            remote, f"{system_id}/{service_id}", "SCA"
        )
    remote = _call_remote_tool(
        "get_sca_scan_result", {"target_id": target_id, "user_id": user_id}
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    if not target_id:
        raise ValueError("target_id is required when using local scan fixtures")
    return _get_scan_result(target_id, "SCA")


@tool(args_schema=RepoIntegrationInput)
def check_repo_integration(package_name: str, ext_url: str) -> dict:
    """Check whether a package's external source URL matches an integrated proxy.

    Returns integrated, repository name and URL where available. This checks
    proxy integration only; it does not download or inspect the package.
    This local implementation contains a small fixture mapping.
    """
    remote = _call_remote_tool(
        "check_repo_integration",
        {"package_name": package_name, "ext_url": ext_url},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    integrations = {
        ("requests", "https://pypi.org/simple"): {
            "integrated": True,
            "repository": "company-pypi-proxy",
            "url": "https://pypi.org/simple",
        }
    }
    return integrations.get(
        (package_name.casefold(), ext_url.rstrip("/").casefold()),
        {"integrated": False, "repository": None, "url": ext_url},
    )


@tool(args_schema=EmptyInput)
def get_external_repos_list() -> list[dict]:
    """Return external repository names, upstream URLs, package formats and internal proxy paths.

    Use to explain a package ecosystem's configured internal download endpoint.
    It does not check a specific package version or whether the package exists.
    This local implementation returns development fixtures.
    """
    remote = _call_remote_tool("get_external_repos_list", {})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    repos = query_external_repos.invoke(EmptyInput())
    external_urls = {
        "pypi": "https://pypi.org/simple/",
        "npm": "https://registry.npmjs.org/",
    }
    return [
        {
            "external_repository_name": repo["name"],
            "external_repository_url": external_urls.get(repo["format"], repo["url"]),
            "package_type": repo["format"],
            "internal_repository_path": repo["url"],
        }
        for repo in repos
    ]


def _execute_security_scan(
    target_type: str,
    target_name: str,
    system_id: str,
    service_id: str,
    user_id: str,
    scan_type: str,
) -> dict:
    return {
        "scan_id": f"SCAN-{uuid4().hex[:8].upper()}",
        "task_id": f"TASK-{uuid4().hex[:8].upper()}",
        "target_type": target_type,
        "target_name": target_name,
        "system_id": system_id,
        "service_id": service_id,
        "user_id": user_id,
        "status": "queued",
        "scan_type": scan_type,
    }


@tool(args_schema=SecretScanInput)
def execute_secret_scan(
    system_id: str,
    service_id: str,
    target_type: str | None = None,
    target_name: str | None = None,
    user_id: str | None = None,
) -> dict:
    """Queue a Secret scan request for an authorized system/service.

    The dedicated Security MCP server requires only system_id and service_id,
    authenticates through the HTTP bearer token, and returns a scan ID. Without
    a dedicated server URL, a local fixture is used for isolated development.
    """
    remote = _call_scan_server_tool(
        "execute_secret_scan",
        {"system_id": system_id, "service_id": service_id},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        response = _decode_json_response(remote, dict)
        return {
            **response,
            "status": str(response.get("status", "queued")).casefold(),
            "scan_id": response.get("scan_id"),
            "target_type": target_type,
            "target_name": target_name,
            "system_id": system_id,
            "service_id": service_id,
            "scan_type": "SECRET",
        }
    remote = _call_remote_tool(
        "execute_secret_scan",
        {
            "target_type": target_type,
            "target_name": target_name,
            "system_id": system_id,
            "service_id": service_id,
            "user_id": user_id,
        },
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return _execute_security_scan(
        target_type or "product",
        target_name or f"{system_id}/{service_id}",
        system_id,
        service_id,
        user_id or "",
        "SECRET",
    )


@tool(args_schema=ScaScanInput)
def execute_sca_scan(
    system_id: str,
    service_id: str,
    target_type: str | None = None,
    target_name: str | None = None,
    user_id: str | None = None,
) -> dict:
    """Queue an SCA scan request for an authorized system/service.

    The dedicated Security MCP server requires only system_id and service_id,
    authenticates through the HTTP bearer token, and returns a scan ID. Without
    a dedicated server URL, a local fixture is used for isolated development.
    """
    remote = _call_scan_server_tool(
        "execute_sca_scan",
        {"system_id": system_id, "service_id": service_id},
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        response = _decode_json_response(remote, dict)
        return {
            **response,
            "status": str(response.get("status", "queued")).casefold(),
            "scan_id": response.get("scan_id"),
            "target_type": target_type,
            "target_name": target_name,
            "system_id": system_id,
            "service_id": service_id,
            "scan_type": "SCA",
        }
    remote = _call_remote_tool(
        "execute_sca_scan",
        {
            "target_type": target_type,
            "target_name": target_name,
            "system_id": system_id,
            "service_id": service_id,
            "user_id": user_id,
        },
    )
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return _execute_security_scan(
        target_type or "product",
        target_name or f"{system_id}/{service_id}",
        system_id,
        service_id,
        user_id or "",
        "SCA",
    )


@tool(args_schema=SbomExtractionInput)
def trigger_sbom_extraction(scan_id: str) -> dict:
    """Queue asynchronous SBOM extraction for a completed scan ID.

    Returns queued status and a job ID; it does not return an SBOM synchronously.
    This local implementation returns a fixture job.
    """
    remote = _call_remote_tool("trigger_sbom_extraction", {"scan_id": scan_id})
    if remote is not _REMOTE_NOT_CONFIGURED:
        return remote
    return {"status": "queued", "scan_id": scan_id, "job_id": f"SBOM-{uuid4().hex[:8].upper()}"}