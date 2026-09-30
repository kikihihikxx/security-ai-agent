import os


def create_llm():
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().casefold()

    if provider in {"gemini", "google", "google-gemini"}:
        from .gemini import create_gemini_llm

        return create_gemini_llm()
    if provider in {"corporate", "company", "internal"}:
        from .corporate import create_corporate_llm

        return create_corporate_llm()

    raise ValueError(
        f"지원하지 않는 LLM_PROVIDER입니다: {provider}. "
        "gemini 또는 corporate를 사용하세요."
    )
