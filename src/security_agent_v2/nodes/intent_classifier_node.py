import os
import re
from typing import Literal

from langchain_core.messages import HumanMessage
from pydantic import BaseModel, Field

from security_agent_v2.prompts.intent_classifier_prompt import (
    INTENT_CLASSIFIER_SYSTEM_PROMPT,
)
from security_agent_v2.states.state import SecurityAgentState
from .common import latest_user_text


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


class IntentClassification(BaseModel):
    category: IntentCategory = Field(
        description="사용자가 현재 메시지에서 가장 우선적으로 요청한 의도 분류"
    )


_CI_PR_TERMS = (
    "ci/cd",
    "cicd",
    "pipeline",
    "파이프라인",
    "pull request",
    "pr ",
    "pr(",
    "pr#",
)
_STATUS_TERMS = (
    "통과",
    "상태",
    "결과",
    "스캔",
    "검사",
    "확인",
    "passed",
    "status",
    "result",
    "pass",
)
_STATIC_SCAN_TERMS = (
    "sql injection",
    "sql 인젝션",
    "xss",
    "sast",
    "static analysis",
    "정적분석",
    "정적 분석",
    "코드에서",
    "이 코드",
    "소스코드",
    "소스 코드",
    "하드코딩된 secret",
    "하드코딩된 시크릿",
    "hard-coded secret",
    "hardcoded secret",
    "인프라 설정 분석",
    "infrastructure config analysis",
)
_ANALYSIS_TERMS = (
    "점검",
    "검사",
    "분석",
    "탐지",
    "찾아",
    "검토",
    "scan",
    "check",
    "review",
    "analyze",
    "analysis",
    "inspect",
    "봐줘",
    "알려줘",
)
_CAPABILITY_TERMS = (
    "무슨 일을",
    "뭘 할 수",
    "무엇을 할 수",
    "어떤 걸 할 수",
    "어떤 일을 할",
    "할 수 있",
    "할수있",
    "뭘 도와",
    "무엇을 도와",
    "어떤 질문",
    "질문 예시",
    "질문 샘플",
    "사용 예시",
    "무엇을 할",
    "핵심 기능",
    "지원 기능",
    "지원하는 기능",
    "어떤 기능",
    "사용법",
    "어떤 데이터",
    "무슨 데이터",
    "무엇을 보내",
    "무엇을 입력",
    "어떤 파일",
    "입력 포맷",
    "분석 가능한",
    "분석 가능",
    "분석 범위",
    "한계점",
    "한계가",
    "지원 여부",
    "지원하나요",
    "지원해",
    "가능하",
    "what can you do",
    "your capabilities",
    "what data",
    "supported features",
    "limitations",
    "do you support",
    "can you",
)
_REMEDIATION_TERMS = (
    "조치",
    "수정",
    "고치",
    "해결",
    "대응",
    "remediation",
    "fix",
    "remediate",
    "보고서",
    "리포트",
    "우선순위",
    "경영진",
    "개발팀",
)
_RESULT_VIEW_TERMS = (
    "보여줘",
    "보여 줘",
    "보여",
    "조회",
    "알려줘",
    "알려 줘",
    "show",
    "display",
    "view",
)
_EXPLICIT_SCAN_ACTION_TERMS = (
    "실행",
    "돌려",
    "시작",
    "스캔해",
    "점검해",
    "run",
    "execute",
    "start",
    "scan now",
)


def _classify_rules(text: str) -> IntentCategory:
    lowered = text.casefold()
    compact = re.sub(r"[\s?!.,:;。？！、]+", "", lowered)

    if any(term in lowered for term in _CI_PR_TERMS) and any(
        term in lowered for term in _STATUS_TERMS
    ):
        return "unsupported_ci_status"
    if any(term in lowered for term in _STATIC_SCAN_TERMS) and any(
        term in lowered for term in _ANALYSIS_TERMS
    ):
        return "unsupported_code_scan"
    if any(term in lowered for term in _CAPABILITY_TERMS):
        return "capability_guide"
    if any(term in lowered for term in _REMEDIATION_TERMS):
        return "remediation"
    if compact in {
        "외부저장소",
        "externalrepository",
        "보안점검",
        "securityscan",
        "패키지",
        "package",
    }:
        return "feature_discovery"

    has_result_intent = any(
        term in lowered for term in ("결과", "이력", "history", "result")
    )
    has_scan_intent = any(
        term in lowered
        for term in (
            "scan",
            "security",
            "vulnerability",
            "cve",
            "secret",
            "sca",
            "sbom",
            "스캔",
            "보안",
            "취약점",
            "비밀",
            "시크릿",
            "점검",
        )
    )
    if has_result_intent and has_scan_intent:
        return "scan_result"

    if any(term in lowered for term in ("secret", "credential", "시크릿", "비밀")):
        return "secret_scan"
    if any(
        term in lowered
        for term in ("sca", "cve", "vulnerability", "dependency", "취약점", "의존성")
    ):
        return "sca_scan"
    if any(
        term in lowered
        for term in ("저장소", "리포지토리", "repository", "repo", "proxy")
    ):
        if any(
            term in lowered
            for term in (
                "다운로드",
                "다운받",
                "다운 받",
                "설치",
                "사용",
                "download",
                "install",
                "연동",
            )
        ) and any(
            term in lowered for term in ("패키지", "dependency", "의존성", "package")
        ):
            return "package_download"
        return "repository"
    if any(term in lowered for term in ("빌드", "build")):
        return "package_build"
    if any(
        term in lowered
        for term in ("baseline", "베이스라인", "패키지 생성", "패키지 등록")
    ):
        return "package_create"
    if any(term in lowered for term in ("패키지", "package")):
        if any(
            term in lowered
            for term in ("다운로드", "다운받", "다운 받", "설치", "사용", "download", "install")
        ):
            return "package_download"
        return "package_create"
    if has_scan_intent:
        return "scan_result" if has_result_intent else "sca_scan"
    return "unknown"


def _heuristic_route(text: str) -> str:
    """Compatibility helper that maps deterministic intent categories to agents."""
    category = _classify_rules(text)
    if category in {
        "capability_guide",
        "unsupported_code_scan",
        "unsupported_ci_status",
        "remediation",
    }:
        return "SupportGuide"
    if category in {"repository", "package_download"}:
        return "RepoAgent"
    if category in {"package_create", "package_build"}:
        return "PackagingAgent"
    if category in {"sca_scan", "secret_scan", "scan_result"}:
        return "SecurityScanAgent"
    if category == "feature_discovery":
        return "FeatureDiscovery"
    return "UnknownIntent"


def intent_classifier_node(state: SecurityAgentState) -> dict:
    """Use the LLM to classify the latest request before routing to a specialist."""
    text = latest_user_text(state.get("messages", []))
    pending_options = state.get("pending_feature_options") or []
    selection = text.strip()
    if selection.isdigit() and 1 <= int(selection) <= len(pending_options):
        return {"intent_category": "feature_discovery"}

    llm_router_setting = os.getenv("ENABLE_LLM_ROUTER", "true").strip().casefold()
    if llm_router_setting in {"0", "false", "no", "off"}:
        category = _classify_rules(text)
    elif llm_router_setting not in {"1", "true", "yes", "on"}:
        raise ValueError(
            "ENABLE_LLM_ROUTER must be a boolean value (true or false)"
        )
    else:
        from security_agent_v2.model.factory import create_llm

        result = create_llm().with_structured_output(IntentClassification).invoke(
            [
                ("system", INTENT_CLASSIFIER_SYSTEM_PROMPT),
                HumanMessage(content=text),
            ]
        )
        if not isinstance(result, IntentClassification):
            raise TypeError("Intent classifier returned an invalid structured response")
        category = result.category

    if (
        category in {"unknown", "sca_scan", "secret_scan"}
        and any(term in text.casefold() for term in _RESULT_VIEW_TERMS)
        and not any(
            term in text.casefold() for term in _EXPLICIT_SCAN_ACTION_TERMS
        )
    ):
        has_previous_scan = bool(
            state.get("scan_status")
            or state.get("scan_id")
            or state.get("scan_task_ids")
            or (
                state.get("system_id")
                and state.get("service_id")
                and state.get("scan_type")
            )
        )
        category = "scan_result" if has_previous_scan else "unknown"
    return {"intent_category": category}


def route_after_classification(state: SecurityAgentState) -> str:
    category = state.get("intent_category", "unknown")
    text = latest_user_text(state.get("messages", []))
    if text.strip().isdigit() and state.get("pending_feature_options"):
        return "init_context"
    if category in {
        "repository",
        "package_download",
        "package_create",
        "package_build",
        "sca_scan",
        "secret_scan",
        "scan_result",
    }:
        return "init_context"
    if category == "remediation":
        return "init_context" if state.get("actionable_report") else "SupportGuide"
    if category in {
        "capability_guide",
        "unsupported_code_scan",
        "unsupported_ci_status",
    }:
        return "SupportGuide"
    if category == "feature_discovery":
        return "FeatureDiscovery"
    return "UnknownIntent"
