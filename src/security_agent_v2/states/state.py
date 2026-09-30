from typing import Annotated, Literal, Sequence, TypedDict
import operator

from langchain_core.messages import BaseMessage


AgentName = Literal[
    "RepoAgent", "PackagingAgent", "SecurityScanAgent",
    "FeatureDiscovery", "SupportGuide", "UnknownIntent",
]
IntentCategory = Literal[
    "capability_guide",
    "repository",
    "package_download",
    "package_create",
    "package_build",
    "sca_scan",
    "secret_scan",
    "scan_result",
    "remediation",
    "unsupported_code_scan",
    "unsupported_ci_status",
    "feature_discovery",
    "unknown",
]


class SecurityAgentState(TypedDict, total=False):
    """Persistent state shared by the supervisor and every specialist node."""

    messages: Annotated[Sequence[BaseMessage], operator.add]
    next_agent: AgentName | None
    intent_category: IntentCategory | None
    jwt_claims: dict
    mcp_tool_results: dict
    accessible_product_groups: list[dict]
    current_product_group: str | None
    repo_target_type: Literal["internal", "external"] | None
    repo_name: str | None
    external_proxy_url: str | None
    approval_line: list[dict]
    approval_ticket_id: str | None
    approval_confirmed: bool
    package_action: Literal["create", "build"] | None
    target_internal_repo: str | None
    package_name: str | None
    build_tool: str | None
    build_tool_version: str | None
    git_url: str | None
    git_branch: str | None
    manifest_path: str | None
    build_status: str | None
    scan_target_type: Literal["package", "product"] | None
    scan_target_name: str | None
    system_id: str | None
    service_id: str | None
    scan_type: Literal["SCA", "SECRET", "ALL"] | None
    actionable_report: dict | None
    sbom_extracted: bool
    request_type: str | None
    scan_status: str | None
    scan_id: str | None
    scan_task_ids: dict | None
    target_keyword: str | None
    product_id: str | None
    package_name: str | None
    result_target_id: str | None
    result_scan_type: Literal["SCA", "SECRET"] | None
    pending_feature_options: list[dict] | None
    resolved_user_request: str | None


class RepoAgentState(SecurityAgentState, total=False):
    pass


class PackagingAgentState(SecurityAgentState, total=False):
    pass


class SecurityScanAgentState(SecurityAgentState, total=False):
    pass
