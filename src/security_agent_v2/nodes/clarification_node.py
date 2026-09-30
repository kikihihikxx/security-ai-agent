from langchain_core.messages import AIMessage

from security_agent_v2.states.state import SecurityAgentState
from .common import latest_user_text


def clarification_node(state: SecurityAgentState) -> dict:
    """Tell the user when the request does not match a supported intent."""
    text = latest_user_text(state.get("messages", [])).casefold()
    if any(term in text for term in ("보여줘", "보여 줘", "보여", "show", "display")):
        message = (
            "결과를 조회하시려는 건가요, 새 보안점검을 실행하시려는 건가요? "
            "의도를 다시 말씀해주세요. 확인 없이 새 점검을 실행하지 않았습니다."
        )
    else:
        message = (
            "요청하신 내용을 이해하지 못했습니다. "
            "저장소, 패키지, SCA 점검 또는 Secret 점검 중 "
            "원하시는 작업을 구체적으로 말씀해주세요."
        )
    return {
        "messages": [AIMessage(content=message)],
        "next_agent": None,
    }
