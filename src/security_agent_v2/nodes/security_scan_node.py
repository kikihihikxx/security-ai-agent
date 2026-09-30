import os
import re
from collections.abc import Mapping

from langchain_core.messages import AIMessage
from langgraph.types import interrupt

from security_agent_v2.states.state import SecurityScanAgentState
from security_agent_v2.tools.mcp_tools import (
    ScaScanInput,
    ScanMCPToolError,
    SecretScanInput,
    ProductListInput,
    ScanResultInput,
    get_pg_product_list,
    get_sca_scan_result,
    get_secret_scan_result,
    execute_sca_scan,
    execute_secret_scan,
)
from .common import request_text, reset_agent_state


def _scan_result_message(result: dict) -> str:
    """Translate the MCP result status into a user-facing response."""
    output_status = str(result.get("sc_output_result", "")).casefold()
    if output_status == "progressing":
        return "보안점검이 아직 진행 중입니다. 완료된 후 다시 결과를 조회해주세요."
    if output_status == "success":
        findings = result.get("findings")
        if isinstance(findings, list) and findings:
            return _format_findings_report(result)
        return str(result.get("summary") or "보안점검이 성공적으로 완료되었습니다.")
    if output_status == "failure":
        reason = (
            result.get("failure_reason")
            or result.get("error_message")
            or result.get("message")
            or "실패 사유가 제공되지 않았습니다."
        )
        return f"보안점검에 실패했습니다. 실패 사유: {reason}"
    return (
        "보안점검 결과의 상태를 확인할 수 없습니다. "
        f"MCP 상태값: {result.get('sc_output_result', '없음')}"
    )


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_LABELS = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "⚪ Low",
}


def _finding_field(finding: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = finding.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _format_findings_report(result: dict) -> str:
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        return str(result.get("summary") or "보안점검이 완료되었습니다.")

    ordered_findings = sorted(
        (finding for finding in findings if isinstance(finding, Mapping)),
        key=lambda finding: _SEVERITY_ORDER.get(
            str(finding.get("severity", "")).casefold(), 4
        ),
    )
    scan_type = str(result.get("scan_type") or "보안")
    target = str(result.get("target_id") or "대상 미제공")
    summary = str(result.get("summary") or f"{target} {scan_type} 점검 완료")
    lines = [
        "### 🛡️ 보안 점검 결과 요약",
        f"**대상:** `{target}` · **유형:** {scan_type}",
        "",
        "| 위험도 | 취약점 항목 | 대상 라인/패키지 | CVSS/CWE |",
        "|---|---|---|---|",
    ]
    for finding in ordered_findings:
        severity = str(finding.get("severity", "")).casefold()
        severity_label = _SEVERITY_LABELS.get(severity, "미분류")
        name = _finding_field(
            finding, "name", "title", "vulnerability", "cve_id", "cve", "message"
        ) or "항목명 미제공"
        location = _finding_field(
            finding, "location", "file", "path", "package_name", "package", "dependency"
        ) or target
        line = _finding_field(finding, "line", "line_number")
        if line:
            location = f"{location}:{line}"
        cvss = _finding_field(finding, "cvss", "cvss_score")
        cwe = _finding_field(finding, "cwe", "cwe_id")
        standard = ", ".join(
            label
            for label in (
                f"CVSS {cvss}" if cvss else None,
                cwe if cwe and cwe.upper().startswith("CWE-") else f"CWE {cwe}" if cwe else None,
            )
            if label
        ) or "도구 결과에 없음"
        lines.append(
            f"| {severity_label} | {name} | `{location}` | {standard} |"
        )

    lines.extend(["", "### 🔍 세부 분석 및 근거", summary])
    for index, finding in enumerate(ordered_findings, start=1):
        name = _finding_field(
            finding, "name", "title", "vulnerability", "cve_id", "cve", "message"
        ) or f"발견 항목 {index}"
        detail = _finding_field(finding, "description", "detail", "message")
        package = _finding_field(
            finding, "package_name", "package", "dependency", "name"
        )
        current_version = _finding_field(
            finding, "installed_version", "current_version", "version"
        )
        fixed_version = _finding_field(
            finding, "fixed_version", "recommended_version", "patched_version"
        )
        remediation = _finding_field(
            finding, "remediation", "recommendation", "solution", "fix"
        )
        fixed_code = _finding_field(finding, "fixed_code", "code_example")
        lines.extend(["", f"{index}. **{name}**"])
        if detail and detail != name:
            lines.append(f"   - 근거: {detail}")
        if package:
            version_text = f" (현재 {current_version})" if current_version else ""
            lines.append(f"   - 패키지: `{package}{version_text}`")
        if fixed_version:
            lines.append(f"   - 수정 버전: `{fixed_version}`")
        if remediation:
            lines.append(f"   - 권장 조치: {remediation}")
        elif fixed_version:
            lines.append(
                "   - 권장 조치: 해당 패키지를 수정 버전 이상으로 올리고 잠금 파일을 갱신한 뒤 재점검하세요."
            )
        else:
            lines.append(
                "   - 권장 조치: 결과에 수정 버전/공급자 권고가 없어 정확한 업데이트 버전을 추정하지 않습니다. "
                "패키지 및 영향 버전을 백엔드 결과와 Advisory에서 확인하세요."
            )
        if fixed_code:
            lines.extend(["   - 제공된 수정 예시:", "", "```", fixed_code, "```"])
        elif fixed_version and package:
            ecosystem = str(
                finding.get("ecosystem") or finding.get("package_ecosystem") or ""
            ).casefold()
            if ecosystem in {"pypi", "python", "pip"}:
                lines.extend(
                    [
                        "   - manifest 수정 예시 (`requirements.txt`; 잠금 파일도 재생성):",
                        "",
                        "```text",
                        f"{package}=={fixed_version}",
                        "```",
                    ]
                )
            elif ecosystem in {"npm", "node", "javascript"}:
                lines.extend(
                    [
                        "   - manifest 수정 예시 (`package.json`; 기존 dependencies/devDependencies 항목을 갱신):",
                        "",
                        "```json",
                        "{",
                        f'  "{package}": "{fixed_version}"',
                        "}",
                        "```",
                    ]
                )
    lines.extend(
        [
            "",
            "CVSS/CWE 또는 수정 코드가 결과에 포함되지 않은 항목은 값을 추정하지 않았습니다.",
        ]
    )
    return "\n".join(lines)


def _is_remediation_request(text: str) -> bool:
    lowered = text.casefold()
    return any(
        term in lowered
        for term in (
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
    )


def _aggregate_scan_status(results: list[dict]) -> str:
    statuses = {str(result.get("sc_output_result", "")).casefold() for result in results}
    if "progressing" in statuses:
        return "progressing"
    if "failure" in statuses:
        return "failure"
    if statuses == {"success"}:
        return "success"
    return "unknown"


def security_scan_node(state: SecurityScanAgentState) -> dict:
    text = request_text(state)
    lowered = text.casefold()
    user_id = state.get("jwt_claims", {}).get("user_id")
    if not user_id:
        return {
            "messages": [AIMessage(content="보안 점검을 위해 인증된 user_id가 필요합니다.")],
            **reset_agent_state(),
        }
    if _is_remediation_request(text):
        report = state.get("actionable_report")
        results = report.get("results", []) if isinstance(report, dict) else []
        if results and isinstance(results[-1], dict):
            previous_result = results[-1]
            output_status = str(
                previous_result.get("sc_output_result", "")
            ).casefold()
            if output_status != "success":
                response = _scan_result_message(previous_result)
            elif previous_result.get("findings"):
                response = _format_findings_report(previous_result)
            else:
                response = (
                    "이전 점검은 완료되었지만 상세 취약점 항목이 결과에 포함되지 않았습니다. "
                    "근거가 없는 수정 코드나 위험도는 추정하지 않습니다. "
                    "백엔드 상세 결과를 확인하거나 SCA/Secret 결과를 다시 조회해주세요."
                )
        else:
            response = (
                "이 대화방에는 조치할 수 있는 스캔 결과가 없습니다. "
                "먼저 등록된 권한 대상의 SCA/Secret 점검을 실행하고 결과를 조회해주세요. "
                "결과에 포함되지 않은 취약점, 수정 버전, 코드는 추정하지 않습니다."
            )
        update = reset_agent_state()
        update["actionable_report"] = report
        update["messages"] = [AIMessage(content=response)]
        return update

    if (
        os.getenv("SECURITY_SCAN_MCP_URL", "").strip()
        and not os.getenv("SECURITY_SCAN_MCP_AUTH_TOKEN", "").strip()
        and not os.getenv("SECURITY_MCP_AUTH_TOKEN", "").strip()
    ):
        update = reset_agent_state()
        update["messages"] = [
            AIMessage(
                content=(
                    "보안 MCP 서버 인증 토큰이 설정되어 있지 않아 보안점검을 진행할 수 없습니다. "
                    "에이전트 실행 환경에 유효한 `devops-admin` Bearer JWT를 "
                    "`SECURITY_SCAN_MCP_AUTH_TOKEN`으로 설정한 뒤 서버를 재시작해주세요. "
                    "토큰은 채팅에 입력하지 마세요."
                )
            )
        ]
        return update

    is_result_request = any(
        word in lowered for word in ("결과", "이력", "result", "history")
    ) or state.get("intent_category") == "scan_result"
    is_result_request = is_result_request and not any(
        word in lowered for word in ("스캔해", "점검해", "scan now", "실행")
    )
    if is_result_request:
        has_secret_result_intent = any(
            word in lowered
            for word in ("secret", "credential", "시크릿", "민감정보", "비밀")
        )
        has_sca_result_intent = bool(re.search(r"\bsca\b", lowered)) or any(
            word in lowered
            for word in ("cve", "vulnerability", "dependency", "취약점", "의존성")
        )
        if has_secret_result_intent and has_sca_result_intent:
            scan_type = None
        elif has_secret_result_intent:
            scan_type = "SECRET"
        elif has_sca_result_intent:
            scan_type = "SCA"
        else:
            scan_type = None

        if scan_type is None:
            while scan_type not in {"SECRET", "SCA"}:
                selected_type = str(
                    interrupt(
                        {
                            "type": "result_scan_type",
                            "message": "어떤 점검 결과를 조회할까요? (1. Secret, 2. SCA)",
                        }
                    )
                ).strip().upper()
                selected_type = re.sub(
                    r"\s*번(?:\s*이요|\s*요)?$", "", selected_type
                )
                scan_type = {"1": "SECRET", "2": "SCA"}.get(
                    selected_type, selected_type
                )

        products = get_pg_product_list.invoke(ProductListInput(user_id=user_id))
        if not products:
            return {
                "messages": [AIMessage(content="조회할 수 있는 보안점검 대상이 없습니다.")],
                **reset_agent_state(),
            }
        options = []
        for index, product in enumerate(products, start=1):
            target_label = product.get("git_repo_url") or product.get(
                "package_name"
            ) or product.get("product_id") or "저장소 URL 미제공"
            options.append(
                f"{index}. System ID: {product['system_id']} / "
                f"Service ID: {product['service_id']} / Repository: {target_label}"
            )
        selected_product = None
        while selected_product is None:
            selection = str(
                interrupt(
                    {
                        "type": "result_target",
                        "message": "결과를 조회할 시스템/서비스를 선택해주세요.\n"
                        + "\n".join(options),
                        "options": products,
                    }
                )
            ).strip()
            selection = re.sub(r"\s*번(?:\s*이요|\s*요)?$", "", selection)
            if selection.isdigit() and 1 <= int(selection) <= len(products):
                selected_product = products[int(selection) - 1]
        target = (
            selected_product.get("package_name")
            if selected_product["service_id"].casefold() == "sdep"
            else selected_product.get("product_id")
        ) or selected_product.get("git_repo_url") or (
            f"{selected_product['system_id']}/{selected_product['service_id']}"
        )
        try:
            result = (
                get_secret_scan_result.invoke(
                    ScanResultInput(
                        system_id=selected_product["system_id"],
                        service_id=selected_product["service_id"],
                        target_id=target,
                        user_id=user_id,
                    )
                )
                if scan_type == "SECRET"
                else get_sca_scan_result.invoke(
                    ScanResultInput(
                        system_id=selected_product["system_id"],
                        service_id=selected_product["service_id"],
                        target_id=target,
                        user_id=user_id,
                    )
                )
            )
        except ScanMCPToolError as error:
            if error.result_not_found:
                message = (
                    f"{scan_type} 점검 결과를 아직 찾지 못했습니다. "
                    "점검이 완료되지 않았거나 해당 시스템/서비스에 저장된 결과가 없습니다. "
                    "점검 상태를 확인한 뒤 다시 조회해주세요."
                )
            else:
                message = (
                    f"{scan_type} 결과 조회에 실패했습니다. "
                    "인증·권한, MCP 서버 연결 및 점검 완료 상태를 확인한 뒤 다시 시도해주세요."
                )
            return {"messages": [AIMessage(content=message)]}
        update = reset_agent_state()
        output_status = str(result.get("sc_output_result", "")).casefold()
        update.update(
            {
                "scan_status": output_status or "unknown",
                "system_id": selected_product["system_id"],
                "service_id": selected_product["service_id"],
                "scan_target_name": target,
                "actionable_report": {"results": [result], "scan_type": scan_type},
                "messages": [AIMessage(content=_scan_result_message(result))],
            }
        )
        return update

    has_sca = bool(re.search(r"\bsca\b", lowered)) or any(
        word in lowered for word in ("cve", "vulnerability", "dependency", "취약점", "의존성")
    )
    has_secret = any(word in lowered for word in ("secret", "credential", "시크릿", "비밀"))
    scan_type = state.get("scan_type")
    if not scan_type and not (has_sca or has_secret):
        scan_type = str(
            interrupt(
                {
                    "type": "scan_type",
                    "message": "어떤 점검을 진행하시겠습니까? (1. SECRET, 2. SCA)",
                }
            )
        ).strip().upper()
        scan_type = {"1": "SECRET", "2": "SCA", "SECRET": "SECRET", "SCA": "SCA"}.get(scan_type)
        if scan_type is None:
            scan_type = str(
                interrupt(
                    {
                        "type": "scan_type",
                        "message": "SECRET 또는 SCA 중 하나를 입력해주세요.",
                    }
                )
            ).strip().upper()
            scan_type = {"1": "SECRET", "2": "SCA", "SECRET": "SECRET", "SCA": "SCA"}.get(scan_type)
    scan_type = scan_type or (
        "SECRET"
        if has_secret and not has_sca
        else "SCA"
        if has_sca and not has_secret
        else "ALL"
    )
    selected_product = None
    if not state.get("system_id") or not state.get("service_id") or not state.get("scan_target_name"):
        products = get_pg_product_list.invoke(ProductListInput(user_id=user_id))
        if not products:
            return {
                "messages": [AIMessage(content="보안 점검 권한이 있는 System/Service가 없습니다.")],
                **reset_agent_state(),
            }
        options = []
        for index, product in enumerate(products, start=1):
            target_label = product.get("git_repo_url") or product.get(
                "package_name"
            ) or product.get("product_id") or "저장소 URL 미제공"
            options.append(
                f"{index}. System ID: {product['system_id']} / "
                f"Service ID: {product['service_id']} / Repository: {target_label}"
            )
        while selected_product is None:
            selection = str(
                interrupt(
                    {
                        "type": "scan_target_selection",
                        "message": (
                            "스캔할 시스템/서비스의 번호를 선택해주세요.\n"
                            + "\n".join(options)
                        ),
                        "options": products,
                    }
                )
            ).strip()
            if selection.isdigit() and 1 <= int(selection) <= len(products):
                selected_product = products[int(selection) - 1]
    else:
        selected_product = {
            "system_id": state["system_id"],
            "service_id": state["service_id"],
            "platform": state.get("scan_target_type"),
            "package_name": state["scan_target_name"],
            "product_id": state["scan_target_name"],
        }

    system_id = selected_product["system_id"]
    service_id = selected_product["service_id"]
    target_type = "package" if service_id.casefold() == "sdep" else "product"
    target = (
        selected_product.get("package_name")
        if target_type == "package"
        else selected_product.get("product_id")
    ) or selected_product.get("git_repo_url") or f"{system_id}/{service_id}"

    scan_inputs = {
        "system_id": system_id,
        "service_id": service_id,
        "target_type": target_type,
        "target_name": target,
        "user_id": user_id,
    }
    raw_results = (
        [
            execute_secret_scan.invoke(SecretScanInput(**scan_inputs)),
            execute_sca_scan.invoke(ScaScanInput(**scan_inputs)),
        ]
        if scan_type == "ALL"
        else [
            (
                execute_secret_scan.invoke(SecretScanInput(**scan_inputs))
                if scan_type == "SECRET"
                else execute_sca_scan.invoke(ScaScanInput(**scan_inputs))
            )
        ]
    )
    scan_ids = {
        result["scan_type"]: result.get("scan_id") or result.get("task_id")
        for result in raw_results
        if result.get("scan_id") or result.get("task_id")
    }
    update = reset_agent_state()
    update.update(
        {
            "scan_target_type": target_type,
            "scan_target_name": target,
            "system_id": system_id,
            "service_id": service_id,
            "scan_type": scan_type,
            "scan_status": "awaiting_result",
            "scan_target_name": target,
            "scan_id": raw_results[0].get("scan_id"),
            "scan_task_ids": scan_ids,
            "messages": [
                AIMessage(
                    content=(
                        "보안 점검을 요청했습니다. 점검이 완료되면 "
                        "'보안점검 결과를 보여줘'라고 요청해주세요.\n"
                        + "\n".join(
                            f"- {scan_name} Scan ID: {scan_id}"
                            for scan_name, scan_id in scan_ids.items()
                        )
                    )
                )
            ],
        }
    )
    return update
