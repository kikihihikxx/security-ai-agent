from security_agent_v2.states.state import SecurityAgentState
from security_agent_v2.tools.mcp_tools import UserIdInput, get_accessible_product_groups


def init_context_node(state: SecurityAgentState) -> dict:
    user_id = state.get("jwt_claims", {}).get("user_id")
    groups = get_accessible_product_groups.invoke(UserIdInput(user_id=user_id))
    return {"accessible_product_groups": groups, "mcp_tool_results": {"accessible_product_groups": groups}}
