from langchain_core.messages import AIMessage
from langgraph.types import interrupt

from security_agent_v2.states.state import PackagingAgentState
from security_agent_v2.tools.mcp_tools import (
    PackageBaselineInput,
    PackageInput,
    PackageNameInput,
    create_package_baseline,
    trigger_build,
    validate_package_name,
)
from .common import request_text, reset_agent_state, value, word_after


def packaging_agent_node(state: PackagingAgentState) -> dict:
    text = request_text(state)
    action = state.get("package_action") or (
        "build" if any(word in text.casefold() for word in ("build", "빌드")) else "create"
    )
    package_name = state.get("package_name") or value(text, "package", "name") or word_after(text, "package")
    if not package_name:
        package_name = str(interrupt({"type": "package_input", "message": "패키지 이름을 알려주세요."})).strip()
    if action == "build":
        result = trigger_build.invoke(PackageInput(package_name=package_name))
        update = reset_agent_state()
        update["messages"] = [AIMessage(content=f"빌드를 요청했습니다. Build ID: {result['build_id']}")]
        return update

    repo = state.get("target_internal_repo") or value(text, "repo", "repository") or word_after(text, "repo", "repository")
    if not repo:
        repo = str(interrupt({"type": "package_input", "message": "대상 Repo를 알려주세요."})).strip()
    duplicate = validate_package_name.invoke(
        PackageNameInput(package_name=package_name, repo_name=repo)
    )
    if not duplicate.get("valid"):
        corrected = interrupt({"type": "duplicate_package", "message": "패키지 이름이 중복됩니다. 다른 이름을 입력해주세요."})
        package_name = str(corrected).strip()
        duplicate = validate_package_name.invoke(
            PackageNameInput(package_name=package_name, repo_name=repo)
        )
        if not duplicate.get("valid"):
            return {"messages": [AIMessage(content="여전히 중복된 패키지 이름입니다. 다시 시도해주세요.")], **reset_agent_state()}

    package_data = {
        "repo_name": repo,
        "package_name": package_name,
        "build_tool": state.get("build_tool") or value(text, "tool", "build_tool") or "maven",
        "build_tool_version": state.get("build_tool_version") or value(text, "tool_version", "version") or "3.9",
        "git_url": state.get("git_url") or value(text, "git_url", "url") or "https://git.example.com/example/repo.git",
        "git_branch": state.get("git_branch") or value(text, "branch") or "main",
        "manifest_path": state.get("manifest_path") or value(text, "path", "manifest") or "pom.xml",
    }
    result = create_package_baseline.invoke(PackageBaselineInput(package_data=package_data))
    update = reset_agent_state()
    update["messages"] = [AIMessage(content=f"패키지 baseline을 등록했습니다. Package ID: {result['package_id']}")]
    return update
