import re

from langchain_core.messages import AIMessage
from langgraph.types import interrupt

from security_agent_v2.states.state import RepoAgentState
from security_agent_v2.tools.mcp_tools import (
    ApprovalLineInput,
    EmptyInput,
    ExternalRepoNameInput,
    RepoCreationInput,
    RepoIntegrationInput,
    check_repo_integration,
    get_approval_line,
    get_external_repos_list,
    name_external_repo,
    query_external_repos,
    query_integrated_repos,
    request_repo_creation,
)
from .common import (
    is_repository_lookup,
    request_text,
    reset_agent_state,
    value,
    word_after,
)


def repo_agent_node(state: RepoAgentState) -> dict:
    text = request_text(state)
    lowered = text.casefold()
    package_name = value(text, "package", "패키지") or word_after(text, "package")
    if not package_name:
        package_match = re.search(r"\b([A-Za-z0-9_.-]+)\s*패키지", text, re.IGNORECASE)
        package_name = package_match.group(1) if package_match else None
    is_package_integration_check = (
        package_name is not None
        and any(word in lowered for word in ("연동", "repository", "저장소"))
        and not any(word in lowered for word in ("추가", "생성", "만들", "신청"))
    )
    if is_package_integration_check:
        url_match = re.search(r"https?://[^\s,;]+", text, re.IGNORECASE)
        external_url = value(text, "url", "external_url") or (
            url_match.group(0).rstrip(").,") if url_match else "https://pypi.org/simple"
        )
        result = check_repo_integration.invoke(
            RepoIntegrationInput(package_name=package_name, ext_url=external_url)
        )
        if result["integrated"]:
            message = f"{package_name} 패키지는 사내 저장소에 연동되어 있습니다: {result['repository']}"
        else:
            message = f"{package_name} 패키지는 해당 외부 저장소와 사내 연동되어 있지 않습니다."
        update = reset_agent_state()
        update["messages"] = [AIMessage(content=message)]
        return update

    is_package_download_question = (
        any(word in lowered for word in ("패키지", "package", "의존성", "dependency"))
        and any(
            word in lowered
            for word in ("다운로드", "download", "설치", "install", "사용", "use", "받으려면")
        )
    )
    if is_package_download_question:
        repositories = get_external_repos_list.invoke(EmptyInput())
        package_confirmation = (
            f"{package_name} 패키지를 말씀하시는 거군요!\n"
            if package_name
            else ""
        )
        url_match = re.search(r"https?://[^\s,;]+", text, re.IGNORECASE)
        external_url = (
            value(text, "url", "external_url")
            or (url_match.group(0).rstrip(").,") if url_match else None)
        )
        if not external_url and package_name:
            package_type = (
                "npm"
                if any(word in lowered for word in ("npm", "node", "javascript"))
                else "pypi"
            )
            external_url = (
                "https://registry.npmjs.org/"
                if package_type == "npm"
                else "https://pypi.org/simple/"
            )
        matched = [
            repo for repo in repositories
            if external_url
            and (
                external_url.rstrip("/").casefold()
                == repo["external_repository_url"].rstrip("/").casefold()
                or external_url.casefold() in repo["external_repository_url"].casefold()
            )
        ]
        if matched:
            repository = matched[0]
            message = (
                f"{package_confirmation}"
                f"사내 연동 저장소 {repository['external_repository_name']}를 사용하세요.\n"
                f"사외 저장소 URL: {repository['external_repository_url']}\n"
                f"패키지 유형: {repository['package_type']}\n"
                f"사내 저장소 URL/path: {repository['internal_repository_path']}\n"
                f"{package_name} 패키지는 위 사내 {repository['package_type']} 저장소에서 "
                "다운로드할 수 있습니다."
            )
        elif external_url:
            message = (
                f"{package_confirmation}"
                f"요청하신 사외 저장소({external_url})는 현재 사내 연동 목록에 없습니다.\n"
                "사내 다운로드를 위해 먼저 외부 저장소 연동을 신청해야 합니다."
            )
        else:
            lines = [
                f"- {repo['external_repository_name']}: "
                f"{repo['external_repository_url']} ({repo['package_type']})"
                for repo in repositories
            ]
            message = (
                f"{package_confirmation}"
                "패키지 다운로드/사용을 위해 확인할 사내 연동 외부 저장소 목록입니다.\n"
                + "\n".join(lines)
                + "\n사용하려는 패키지의 사외 저장소 URL을 알려주시면 연동 여부를 확인해드리겠습니다."
            )
        update = reset_agent_state()
        update["messages"] = [AIMessage(content=message)]
        return update

    is_repository_query = (
        is_repository_lookup(text)
        and not any(
            word in lowered
            for word in ("create", "new", "생성", "만들", "신규", "추가", "신청")
        )
    )
    if is_repository_query:
        is_external_query = any(
            word in lowered for word in ("external", "proxy", "외부", "프록시")
        )
        repositories = (
            query_external_repos.invoke(EmptyInput())
            if is_external_query
            else query_integrated_repos.invoke(EmptyInput())
        )
        lines = [
            f"- {repo['name']} [{repo['repo_type']}]: {repo['url']}"
            for repo in repositories
        ]
        update = reset_agent_state()
        update["messages"] = [
            AIMessage(
                content=(
                    "외부 연동 저장소 목록입니다.\n"
                    if is_external_query
                    else "사내에 연동된 저장소 목록입니다.\n"
                )
                + "\n".join(lines)
            )
        ]
        return update

    target_type = state.get("repo_target_type") or (
        "external"
        if any(word in lowered for word in ("external", "proxy", "외부", "사외", "프록시"))
        else "internal"
    )
    external_proxy_url = state.get("external_proxy_url") or value(text, "url", "proxy_url")
    if not external_proxy_url:
        url_match = re.search(r"https?://[^\s,;]+", text, re.IGNORECASE)
        external_proxy_url = url_match.group(0).rstrip(").,") if url_match else None

    if target_type == "external" and not external_proxy_url:
        external_proxy_url = str(
            interrupt(
                {
                    "type": "external_repo_url",
                    "message": "추가할 사외 저장소 URL을 알려주세요.",
                }
            )
        ).strip()

    repo_name = state.get("repo_name") or value(text, "repo", "name") or word_after(text, "repo", "repository")
    if target_type == "external":
        naming = name_external_repo.invoke(
            ExternalRepoNameInput(external_proxy_url=external_proxy_url)
        )
        if not naming.get("valid"):
            external_proxy_url = str(
                interrupt(
                    {
                        "type": "external_repo_url",
                        "message": "올바른 http 또는 https 형식의 사외 저장소 URL을 알려주세요.",
                    }
                )
            ).strip()
            naming = name_external_repo.invoke(
                ExternalRepoNameInput(external_proxy_url=external_proxy_url)
            )
        repo_name = naming["repo_name"]
    repo_name = repo_name or "new-repository"
    group = state.get("current_product_group") or value(text, "group", "product_group")
    if target_type == "internal" and not group:
        group = str(interrupt({"type": "repo_input", "message": "Internal Repo의 Product Group을 알려주세요."})).strip()
    accessible = {g["id"].casefold() for g in state.get("accessible_product_groups", [])}
    if target_type == "internal" and group and group.casefold() not in accessible:
        return {"messages": [AIMessage(content=f"접근 권한이 없는 Product Group입니다: {group}")], **reset_agent_state()}

    line = get_approval_line.invoke(
        ApprovalLineInput(repo_type=target_type, product_group=group)
    )
    decision = interrupt(
        {
            "type": "repo_approval",
            "message": "다음 승인 라인으로 진행할까요? (Yes/No)",
            "approval_line": line,
            "repo": repo_name,
        }
    )
    confirmed = decision is True or str(decision).strip().casefold() in {"yes", "y", "proceed", "진행", "예"}
    if not confirmed:
        return {"messages": [AIMessage(content="승인 요청을 취소했습니다.")], **reset_agent_state()}

    repo_data = {
        "repo_name": repo_name,
        "repo_type": target_type,
        "product_group": group,
        "external_proxy_url": external_proxy_url,
    }
    result = request_repo_creation.invoke(
        RepoCreationInput(repo_data=repo_data, approval_line=line)
    )
    update = reset_agent_state()
    update.update(
        {
            "approval_ticket_id": result["ticket_id"],
            "messages": [AIMessage(content=f"저장소 승인 요청을 생성했습니다. Ticket ID: {result['ticket_id']}")],
        }
    )
    return update
