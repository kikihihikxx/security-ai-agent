from langchain_core.messages import AIMessage

from security_agent_v2.states.state import SecurityAgentState
from .common import latest_user_text, reset_agent_state


def feature_discovery_node(state: SecurityAgentState) -> dict:
    """List supported capabilities when the user provides only a domain keyword."""
    text = latest_user_text(state.get("messages", []))
    normalized = "".join(text.casefold().split())
    options = []
    if "외부저장소" in normalized or "externalrepository" in normalized:
        options = [
            {"route": "RepoAgent", "request": "사내 연동된 외부 저장소 목록 알려줘"},
            {"route": "RepoAgent", "request": "외부 저장소의 패키지 유형과 사외 저장소 URL 알려줘"},
            {"route": "RepoAgent", "request": "패키지가 사내 외부 저장소에 연동되어 있는지 확인해줘"},
            {"route": "RepoAgent", "request": "패키지 다운로드와 사용을 위한 사내 저장소 경로 알려줘"},
        ]
        message = (
            "'외부 저장소'와 관련해 다음 기능을 사용할 수 있습니다.\n"
            "1. 사내 연동된 외부 저장소 목록 조회\n"
            "2. 외부 저장소의 패키지 유형과 사외 저장소 URL 확인\n"
            "3. 패키지가 사내 외부 저장소에 연동되어 있는지 확인\n"
            "4. 패키지 다운로드/사용을 위한 사내 저장소 경로 안내\n"
            "원하시는 기능을 질문해 주세요."
        )
    elif any(keyword in normalized for keyword in ("보안점검", "securityscan", "securitycheck")):
        options = [
            {"route": "SecurityScanAgent", "request": "Secret Scan 보안점검 실행해줘"},
            {"route": "SecurityScanAgent", "request": "SCA 보안점검 실행해줘"},
            {"route": "SecurityScanAgent", "request": "Secret Scan 보안점검 결과 알려줘"},
            {"route": "SecurityScanAgent", "request": "SCA 보안점검 결과 알려줘"},
        ]
        message = (
            "'보안점검'과 관련해 다음 기능을 사용할 수 있습니다.\n"
            "1. Secret Scan 보안점검 실행\n"
            "2. SCA 보안점검 실행\n"
            "3. Secret Scan 결과 조회\n"
            "4. SCA 결과 조회\n"
            "원하시는 점검 유형이나 결과 조회를 말씀해 주세요."
        )
    elif normalized in {"패키지", "package"}:
        options = [
            {"route": "PackagingAgent", "request": "패키지 baseline 등록해줘"},
            {"route": "PackagingAgent", "request": "패키지 빌드 실행해줘"},
            {"route": "RepoAgent", "request": "패키지 다운로드 방법 알려줘"},
        ]
        message = (
            "'패키지'와 관련해 다음 기능을 사용할 수 있습니다.\n"
            "1. 패키지 baseline 등록\n"
            "2. 패키지 빌드 실행\n"
            "3. 패키지 다운로드/사용을 위한 외부 저장소 확인\n"
            "원하시는 기능을 질문해 주세요."
        )
    else:
        message = (
            "입력하신 용어와 관련된 기능을 찾지 못했습니다. "
            "저장소, 패키지, 보안점검 중 원하시는 작업을 질문해 주세요."
        )
    update = reset_agent_state()
    update["pending_feature_options"] = options or None
    update["messages"] = [AIMessage(content=message)]
    return update
