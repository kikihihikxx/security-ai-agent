from langchain_core.messages import AIMessage

from security_agent_v2.states.state import SecurityAgentState
from .common import latest_user_text, reset_agent_state
from .supervisor_node import (
    _is_ci_or_pr_status_request,
    _is_unsupported_source_scan_request,
)


def _capability_guide() -> str:
    return """## Security Agent 지원 기능 안내

저는 오픈소스 취약점 분석(SCA), Secret Scan 점검 및 결과 조회를 할 수 있어요. 그 밖에 저장소 조회와 패키지 등록·빌드도 도와드릴 수 있습니다.

| 기능 | 할 수 있는 일 | 질문 예시 |
|---|---|---|
| 저장소 관리 | 사내·외부 저장소 조회, 패키지 다운로드 경로 안내, 승인 기반 저장소 생성 요청 | "연동된 외부 저장소를 알려줘" / "fastmcp 패키지를 사내에서 다운받으려면 어떻게 해?" |
| 패키지 관리 | 패키지 baseline 등록 및 등록된 패키지 빌드 | "새 패키지 baseline 등록에 필요한 정보를 알려줘" / "payment-pkg 빌드해줘" |
| 보안 점검 | 권한이 있는 등록 대상의 SCA·Secret Scan 실행 및 결과 조회 | "payment-pkg SCA 점검해줘" / "결제 API의 Secret Scan 결과 알려줘" |
| 점검 결과 안내 | 조회된 결과의 finding 요약, 우선순위 및 결과에 포함된 조치 정보 정리 | "방금 조회한 결과에서 우선 조치할 항목을 정리해줘" |

원하시면 위 문장을 그대로 입력하거나, 대상 이름과 원하는 작업을 함께 알려주세요."""


def support_guide_node(state: SecurityAgentState) -> dict:
    text = latest_user_text(state.get("messages", []))
    lowered = text.casefold()

    if _is_ci_or_pr_status_request(text):
        response = """## 요청하신 상태 확인은 현재 지원하지 않습니다

CI/CD 파이프라인의 실시간 검사 통과 여부 조회와 Pull Request 자동 스캔/결과 조회는 현재 연동되어 있지 않습니다. 특정 빌드나 PR이 보안 검사를 통과했는지 확인했다고 답변할 수 없습니다.

### 가능한 대체 방법

1. 등록된 권한 대상의 SCA 또는 Secret 점검을 이 채팅에서 요청하고, 완료 후 결과를 조회하세요.
2. 코드의 일반적인 안전성 설명이 필요하면 변경 코드와 언어/프레임워크를 붙여넣어 질문할 수 있습니다. 다만 자동 SAST 점검 결과로 간주하면 안 됩니다.
3. CI/CD 또는 Git Provider에서 자동 점검을 수행하려면 별도의 파이프라인/PR 연동 기능이 필요합니다."""
    elif _is_unsupported_source_scan_request(text):
        response = """## 인라인 소스 코드 보안 스캔은 현재 미지원입니다

SQL Injection, XSS, 하드코딩된 Secret 등을 코드에서 자동 탐지하는 SAST/정적분석 도구가 연결되어 있지 않습니다. 코드를 붙여넣으셔도 자동 스캔을 수행하거나 취약점이 없다고 판정하지 않습니다.

일반적인 코드 설명이나 안전한 구현 방향은 안내할 수 있습니다. 실제 탐지 결과가 필요하면 조직에서 승인한 SAST 도구를 사용해주세요. 등록된 권한 대상의 의존성 취약점은 SCA 점검을 요청할 수 있습니다."""
    elif any(
        term in lowered
        for term in (
            "수정", "고치", "조치", "해결", "remediation", "fix", "보고서", "리포트"
        )
    ):
        response = """## 구체적인 조치 안내에 필요한 정보가 없습니다

현재 대화방에서 조회한 스캔 결과가 없어 취약점별 우선순위나 수정 코드를 안전하게 제시할 수 없습니다. 먼저 등록된 권한 대상의 SCA/Secret 점검 결과를 조회해주세요.

결과에 취약점, 영향 패키지/버전, 수정 권고 버전이 포함되면 그 근거를 기준으로 조치 순서와 권장 변경을 정리할 수 있습니다. 결과에 없는 수정 버전이나 코드 라인은 추정하지 않습니다."""
    else:
        response = _capability_guide()

    update = reset_agent_state()
    update["messages"] = [AIMessage(content=response)]
    return update
