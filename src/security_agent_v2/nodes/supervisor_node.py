from security_agent_v2.states.state import SecurityAgentState
from .common import latest_user_text
from .intent_classifier_node import _classify_rules, _heuristic_route


def _is_ci_or_pr_status_request(text: str) -> bool:
    return _classify_rules(text) == "unsupported_ci_status"


def _is_unsupported_source_scan_request(text: str) -> bool:
    return _classify_rules(text) == "unsupported_code_scan"


_INTENT_ROUTES = {
    "capability_guide": "SupportGuide",
    "repository": "RepoAgent",
    "package_download": "RepoAgent",
    "package_create": "PackagingAgent",
    "package_build": "PackagingAgent",
    "sca_scan": "SecurityScanAgent",
    "secret_scan": "SecurityScanAgent",
    "scan_result": "SecurityScanAgent",
    "unsupported_code_scan": "SupportGuide",
    "unsupported_ci_status": "SupportGuide",
    "feature_discovery": "FeatureDiscovery",
    "unknown": "UnknownIntent",
}


def supervisor_node(state: SecurityAgentState) -> dict:
    """Route using the category assigned by the graph's input classifier."""
    text = latest_user_text(state.get("messages", []))
    selection = text.strip()
    pending_options = state.get("pending_feature_options") or []
    if selection.isdigit() and len(selection) == 1:
        option_index = int(selection) - 1
        if 0 <= option_index < len(pending_options):
            option = pending_options[option_index]
            return {
                "next_agent": option["route"],
                "resolved_user_request": option["request"],
                "pending_feature_options": None,
            }

    category = state.get("intent_category", "unknown")
    if category == "remediation":
        route = (
            "SecurityScanAgent"
            if state.get("actionable_report")
            else "SupportGuide"
        )
    else:
        route = _INTENT_ROUTES.get(category, "UnknownIntent")
    return {"next_agent": route}
