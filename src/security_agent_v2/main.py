import uuid
from collections.abc import Mapping
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.types import Command

from security_agent_v2.graph import agent_app


def _state_update(value: Any) -> Mapping[str, Any] | None:
    """LangGraph stream 모드별 출력 형식을 상태 업데이트로 정규화합니다."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], Mapping):
        return value[1]
    return None


def _new_conversation_config() -> dict[str, dict[str, str]]:
    return {"configurable": {"thread_id": str(uuid.uuid4())}}


def main() -> None:
    print("DevSecOps Security Agent를 시작합니다.")
    config = _new_conversation_config()
    jwt_claims = {"user_id": "test_user_01", "roles": ["developer"], "department": "platform_engineering"}
    print("종료하려면 '종료' 또는 'exit', 대화 초기화는 '초기화' 또는 'reset'을 입력하세요.\n")
    waiting_for_resume = False

    try:
        while True:
            user_input = input("User: ").strip()
            if user_input.casefold() in {"quit", "exit", "q"}:
                break
            if user_input.casefold() in {"reset", "초기화", "새 대화", "새대화"}:
                config = _new_conversation_config()
                waiting_for_resume = False
                print("\n새 대화를 시작합니다.\n")
                continue

            if waiting_for_resume:
                stream = agent_app.stream(Command(resume=user_input), config)
            else:
                stream = agent_app.stream(
                    {"messages": [HumanMessage(content=user_input)], "jwt_claims": jwt_claims},
                    config,
                )

            waiting_for_resume = False
            for output in stream:
                if "__interrupt__" in output:
                    waiting_for_resume = True
                    interrupt_value = output["__interrupt__"]
                    if isinstance(interrupt_value, tuple):
                        interrupt_value = interrupt_value[0]
                    prompt = getattr(interrupt_value, "value", None)
                    if isinstance(prompt, dict) and prompt.get("message"):
                        print(f"\nAgent: {prompt['message']}")
                for raw_update in output.values():
                    update = _state_update(raw_update)
                    if update is None:
                        continue
                    for message in update.get("messages", []):
                        if getattr(message, "type", None) == "ai":
                            print(f"\nAgent: {message.content}")
            if waiting_for_resume:
                print("\n[입력 대기 중입니다. 위 요청에 답해주세요.]\n")
    except KeyboardInterrupt:
        print("\n\n대화를 종료합니다.")
    except EOFError:
        print("\n\n입력이 종료되어 대화를 종료합니다.")


if __name__ == "__main__":
    main()