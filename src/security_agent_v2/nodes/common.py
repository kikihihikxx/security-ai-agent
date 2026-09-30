import re
from collections.abc import Sequence

from langchain_core.messages import BaseMessage


def latest_user_text(messages: Sequence[BaseMessage]) -> str:
    for message in reversed(messages):
        if getattr(message, "type", None) == "human":
            return str(message.content)
        if isinstance(message, (tuple, list)) and len(message) == 2:
            role, content = message
            if role in {"user", "human"}:
                return str(content)
    return ""


def request_text(state: dict) -> str:
    """Return a feature-menu selection expanded by the supervisor when present."""
    return str(state.get("resolved_user_request") or latest_user_text(state.get("messages", [])))


def value(text: str, *keys: str) -> str | None:
    for key in keys:
        match = re.search(rf"{re.escape(key)}\s*[:=]\s*([^\s,;]+)", text, re.IGNORECASE)
        if match:
            return match.group(1).strip("'\"")
    return None


def word_after(text: str, *keys: str) -> str | None:
    for key in keys:
        match = re.search(rf"\b{re.escape(key)}\b\s+([A-Za-z0-9_.:/-]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def is_repository_lookup(text: str) -> bool:
    """Detect repository listing/status questions without fixed full phrases."""
    lowered = text.casefold()
    has_repository = any(
        token in lowered
        for token in ("repo", "repository", "저장소", "리포지토리", "repository")
    )
    has_lookup_signal = any(
        token in lowered
        for token in (
            "list", "show", "query", "check", "목록", "리스트", "조회",
            "확인", "보여", "알려", "연동", "연결", "integrated",
            "뭐", "무엇", "어떤", "어디", "있지", "있어", "있나요",
            "있습니까", "현황",
        )
    )
    return has_repository and has_lookup_signal


def reset_agent_state() -> dict:
    return {
        "next_agent": None,
        "repo_target_type": None,
        "repo_name": None,
        "external_proxy_url": None,
        "approval_line": [],
        "approval_ticket_id": None,
        "approval_confirmed": False,
        "package_action": None,
        "target_internal_repo": None,
        "package_name": None,
        "build_tool": None,
        "build_tool_version": None,
        "git_url": None,
        "git_branch": None,
        "manifest_path": None,
        "build_status": None,
        "scan_target_type": None,
        "scan_target_name": None,
        "system_id": None,
        "service_id": None,
        "scan_type": None,
        "actionable_report": None,
        "sbom_extracted": False,
        "request_type": None,
        "scan_status": None,
        "scan_id": None,
        "scan_task_ids": None,
        "target_keyword": None,
        "product_id": None,
        "package_name": None,
        "result_target_id": None,
        "result_scan_type": None,
        "pending_feature_options": None,
        "resolved_user_request": None,
    }
