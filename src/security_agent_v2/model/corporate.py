import os

from langchain_openai import ChatOpenAI


def create_corporate_llm() -> ChatOpenAI:
    base_url = os.getenv("CORPORATE_LLM_API_URL") or os.getenv("CORPORATE_LLM_BASE_URL")
    api_key = os.getenv("CORPORATE_LLM_API_KEY")
    model = os.getenv("CORPORATE_LLM_MODEL", "default")

    if not base_url:
        raise ValueError(
            "CORPORATE_LLM_API_URL 또는 CORPORATE_LLM_BASE_URL 환경변수가 필요합니다."
        )
    if not api_key:
        raise ValueError("CORPORATE_LLM_API_KEY 환경변수가 필요합니다.")

    return ChatOpenAI(
        base_url=base_url,
        api_key=api_key,
        model=model,
    )
