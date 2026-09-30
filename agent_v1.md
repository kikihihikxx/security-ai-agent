# Security Agent LangGraph State & Architecture Specification (v3.0)

## 1. Domain Architecture & Business Logic Rules
This section contains critical business rules, domain context, and process logic. You must strictly adhere to these guidelines when implementing the Nodes, Prompts, and State logic.

### 1.1. SDEP Domain Architecture & Hierarchy
The DevSecOps platform (SDEP) follows a strict logical hierarchy:
* **Product Group:** The highest logical group. A user can belong to multiple groups.
* **Internal Repo:** Created *under* a specific Product Group.
* **Package:** Created *under* a specific Internal Repo.
* **External Proxy Repo:** Standalone. Not tied to a Product Group. Available to all developers across the company.
* **Security Scan Targets:** Can be either an internal `Package` (from SDEP) or an external `Product` (from an external DevOps platform). Both ultimately belong to a `Product Group`.

### 1.2. Authorization & Context Flow
* **No Hallucinated Permissions:** Do not assume a user has access to a repo or package.
* **Init Node Enforcement:** The `init_node` uses the User ID from the `jwt_claims` to fetch `accessible_product_groups` via a mock B/E API. 
* **Validation:** All Sub-Agents MUST validate the user's request against this `accessible_product_groups` list (or accessible packages/products list) before executing any action.

### 1.3. Human-in-the-Loop (HITL) Approval Logic
Both Internal Hosted Repos and External Proxy Repos **REQUIRE** an approval process.
* **Process Flow:**
  1. Agent identifies the target repo specifications.
  2. Agent calls the API to fetch the designated `approval_line`.
  3. **Interrupt:** The Agent must display the approval line to the user and ask, *"Do you want to proceed with this approval line?"*
  4. Execution halts here using LangGraph's `interrupt()` API.
  5. **Resume:** Only when the user inputs a confirmation (e.g., "Yes", "Proceed"), the Agent resumes the graph and calls the API to actually create the approval ticket.

### 1.4. Packaging Lifecycle Separation
The `PackagingAgent` handles two distinctly different operations:
1. **Create Package (Baseline Registration):**
   * **Required Input:** Target Repo, Package Name, Build Tool, Build Tool Version, Git URL, Git Branch, Manifest/Folder Path.
   * **Validation:** Must check if the Package Name is duplicated within the target repo before creation.
   * **Result:** Saves the baseline in the SDEP B/E. Does *not* trigger a build.
2. **Build Package (Execution):**
   * **Required Input:** Only the `Package Name`.
   * **Logic:** The SDEP B/E already knows the Git info from the baseline. The Agent just triggers the build pipeline and polls/returns the status.

### 1.5. Security Scanning Rules
The `SecurityScanAgent` has strict operational rules:
1. **Non-Blocking:** The Agent must NEVER block or fail the CI/CD pipeline due to found vulnerabilities.
2. **Actionable Reporting:** Raw CVE lists are forbidden. The LLM must format the raw tool output into developer-friendly actionable items (e.g., "Update `spring-boot` to v3.1.2 in your `pom.xml` to resolve CVE-2023-XXXX.").
3. **Asynchronous SBOM:** The Agent's job ends at reporting. However, immediately after providing the report, it MUST call the mock tool to trigger the Backend SBOM extraction process asynchronously.

---

## 2. Graph State Definition (Decoupled Architecture)
To prevent the Global State from becoming bloated, we separate the state into a **Common Base State** (used by the Supervisor) and **Agent-Specific States** (used by each Sub-graph). 

```python
from typing import TypedDict, Annotated, Sequence, Optional, List
from langchain_core.messages import BaseMessage
import operator

# =========================================================
# [1] Common Base State (Supervisor & Global Context)
# =========================================================
class SecurityAgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    next_agent: Optional[str]            # Routing destination (e.g., "RepoAgent")
    jwt_claims: dict                     # Keycloak JWT payload (User ID, Roles, etc.)
    mcp_tool_results: dict               # Buffer for MCP tool returns
    
    # Common Context Data (Populated via Initialization Node)
    accessible_product_groups: List[dict] 
    current_product_group: Optional[str] # Active Product Group for the conversation

# =========================================================
# [2] Repo Agent Specific State
# =========================================================
class RepoAgentState(SecurityAgentState):
    repo_target_type: Optional[str]      # "internal" | "external"
    repo_name: Optional[str]
    external_proxy_url: Optional[str]    # Used only if target is external
    
    # Approval Context
    approval_line: List[dict]            # Fetched approval line
    approval_ticket_id: Optional[str]
    approval_confirmed: bool             # Human-in-the-loop flag

# =========================================================
# [3] Packaging Agent Specific State
# =========================================================
class PackagingAgentState(SecurityAgentState):
    package_action: Optional[str]        # "create" (register baseline) | "build"
    target_internal_repo: Optional[str]  # Parent repo for the package
    package_name: Optional[str]
    
    # Required for "create" action
    build_tool: Optional[str]            # e.g., "maven", "gradle", "npm"
    build_tool_version: Optional[str]
    git_url: Optional[str]
    git_branch: Optional[str]
    manifest_path: Optional[str]         # Path to pom.xml, package.json, etc.
    
    build_status: Optional[str]          # Status of the triggered build

# =========================================================
# [4] Security Scan Agent Specific State
# =========================================================
class SecurityScanAgentState(SecurityAgentState):
    scan_target_type: Optional[str]      # "package" (SDEP) | "product" (External DevOps)
    scan_target_name: Optional[str]      # Name or ID of the target
    scan_type: Optional[str]             # "SCA" | "SECRET" | "ALL"
    actionable_report: Optional[dict]    # Formatted user-friendly report
    sbom_extracted: bool                 # Flag ensuring B/E SBOM trigger is called



## 3. Sub-Agent Workflows & Mock MCP Tools Requirements
You are building the LangGraph agent before the actual MCP server is ready. Implement all necessary DevSecOps API interactions as standard LangChain @tool functions (Mock Tools).

### 3.1. Initialization / Context Node (Pre-routing)
Action: Before routing, the Agent extracts the User ID from jwt_claims and calls the Product Group API.

Mock Tool: mock_get_accessible_product_groups(user_id)

Effect: Updates accessible_product_groups in the State so the Supervisor and Sub-Agents know exactly what the user is allowed to access.

### 3.2. Repo Agent (Handles Internal & External)
NLU identifies if the user wants an internal or external repo.

If internal, validates if the requested product group is in accessible_product_groups.

Calls mock_get_approval_line(repo_type, product_group) to fetch the required approvers.

Saves to approval_line and [Interrupts] to ask the user: "Here is the approval line. Proceed? (Yes/No)".

On "Yes", calls mock_request_repo_creation(repo_data, approval_line) and returns the Ticket ID.

### 3.3. Packaging Agent
Workflow (Create Package):

Collects required fields.

Calls mock_validate_package_name(package_name, repo_name) to check for duplicates.

Calls mock_create_package_baseline(package_data) to register the package in SDEP.

Workflow (Build Package):

User requests a build.

Agent calls mock_trigger_build(package_name).

### 3.4. Security Scan Agent
Determines if the target is an SDEP Package or a DevOps Product.

Validates user permission using mock_get_accessible_packages() or mock_get_accessible_products().

Triggers scan via mock_run_security_scan(target_type, target_name).

Formats raw results into Actionable Reports.

Strictly calls mock_trigger_sbom_extraction(scan_id) asynchronously after reporting.

## 4. Claude Implementation Guide
LangGraph Setup: Use the provided SecurityAgentState as the single source of truth for the StateGraph.

Conditional Routing: Implement tools_condition or custom routing logic in the Supervisor Node.

Checkpointer: Use MemorySaver() specifically for the Repo Agent's approval confirmation step to pause and resume the graph.

Mock Tools: Implement standard Python functions wrapped with @tool for all APIs mentioned above to simulate the SDEP platform and backend behaviors.

## 5. Directory Structure & File Split Architecture
```Plaintext
security_agent/
├── __init__.py
├── main.py                     # Entry point (Application execution / CLI loop)
├── graph.py                    # LangGraph build, routing, and compilation logic
├── model/
│   ├── __init__.py
│   └── llm_setup.py            # Gemini LLM initialization
├── states/
│   ├── __init__.py
│   └── state.py                # Contains SecurityAgentState and all Sub-States
├── prompts/
│   ├── __init__.py
│   ├── supervisor_prompt.py    # System prompt for Supervisor routing
│   ├── repo_agent_prompt.py    # System prompt for Repo creation & approval
│   ├── packaging_agent_prompt.py 
│   └── security_scan_prompt.py 
├── nodes/
│   ├── __init__.py
│   ├── init_node.py            
│   ├── supervisor_node.py      
│   ├── repo_agent_node.py      
│   ├── packaging_agent_node.py 
│   └── security_scan_node.py   
└── tools/
    ├── __init__.py
    └── mock_mcp_tools.py       # Mock implementations of SDEP & DevOps APIs
## 6. Detailed File Specifications (For Claude)
### 6.1. prompts/ Files
**`prompts/supervisor_prompt.py`**
```python
SUPERVISOR_SYSTEM_PROMPT = """You are the Supervisor Agent for a DevSecOps platform (SDEP).
Your job is to analyze the user's request, check their permissions (JWT claims), and route the request to the correct specialized agent.
Available Agents:
- RepoAgent: For creating or managing Internal (Hosted) or External (Proxy) repositories.
- PackagingAgent: For registering package baselines (git info, build tools) or triggering builds.
- SecurityScanAgent: For running SCA or Secret scans on packages/products.
Do NOT answer the user's question directly. Always route to the appropriate agent.
"""
prompts/repo_agent_prompt.py

```python
REPO_AGENT_SYSTEM_PROMPT = """You are the Repository Management Agent.
You handle creation of both Internal (Hosted) and External (Proxy) Nexus repositories.
STRICT WORKFLOW:
1. Identify if the request is for an Internal or External repo.
2. Call the tool to get the approval line.
3. Present the approval line to the user and ASK FOR CONFIRMATION (Interrupt).
4. Do NOT create the ticket until the user explicitly says "Yes" or "Proceed".
5. Once confirmed, call the tool to create the approval ticket and return the Ticket ID.
"""
prompts/packaging_agent_prompt.py

```python
PACKAGING_AGENT_SYSTEM_PROMPT = """You are the Packaging Agent for the SDEP platform.
You handle two distinct actions: 'create' (baseline) and 'build'.
For 'create': You must gather the target repo, package name, build tool & version, git URL, git branch, and manifest path.
For 'build': You only need the package name to trigger the build.
Always validate package names for duplicates using the provided tool before creating a baseline.
"""
prompts/security_scan_prompt.py

```python
SECURITY_SCAN_SYSTEM_PROMPT = """You are the Security Scanning Agent.
You handle Secret scans and SCA (Open Source Vulnerabilities) for SDEP Packages or External DevOps Products.
STRICT REPORTING RULES:
1. Your final response MUST be an Actionable Report. Do not just list CVEs. 
   - Good: "Update 'log4j' to version 2.17.1 to fix CVE-YYYY-XXXX."
2. Never block the pipeline yourself.
3. After generating the report, you MUST call the tool to asynchronously trigger SBOM extraction for the backend.
"""
6.2. nodes/ Files
nodes/init_node.py

```python
from states.state import SecurityAgentState
from tools.mock_mcp_tools import mock_get_accessible_product_groups

def init_context_node(state: SecurityAgentState):
    """Extracts User ID from JWT and populates accessible product groups before routing."""
    user_id = state.get("jwt_claims", {}).get("user_id")
    groups = mock_get_accessible_product_groups(user_id)
    return {"accessible_product_groups": groups}
nodes/supervisor_node.py

```python
from states.state import SecurityAgentState
from prompts.supervisor_prompt import SUPERVISOR_SYSTEM_PROMPT
# Import LLM...

def supervisor_node(state: SecurityAgentState):
    """Uses LLM with structured output to determine the 'next_agent'."""
    # LLM logic bound with SUPERVISOR_SYSTEM_PROMPT
    # Returns {"next_agent": "RepoAgent" | "PackagingAgent" | "SecurityScanAgent"}
    pass
nodes/repo_agent_node.py

```python
from states.state import RepoAgentState
from prompts.repo_agent_prompt import REPO_AGENT_SYSTEM_PROMPT
from tools.mock_mcp_tools import mock_get_approval_line, mock_request_repo_creation

def repo_agent_node(state: RepoAgentState):
    """
    Sub-graph node for Repo logic.
    * Note for Claude: Implement Human-in-the-loop (HITL) here. 
    If `approval_line` is fetched but `approval_confirmed` is False, return a message to ask the user and use MemorySaver to interrupt.
    """
    pass
nodes/packaging_agent_node.py

```python
from states.state import PackagingAgentState
from prompts.packaging_agent_prompt import PACKAGING_AGENT_SYSTEM_PROMPT
from tools.mock_mcp_tools import mock_validate_package_name, mock_create_package_baseline, mock_trigger_build

def packaging_agent_node(state: PackagingAgentState):
    """Sub-graph node for handling package baseline creation and build triggers."""
    pass
*`nodes/security_scan_node.py`*

```python
from states.state import SecurityScanAgentState
from prompts.security_scan_prompt import SECURITY_SCAN_SYSTEM_PROMPT
from tools.mock_mcp_tools import mock_run_security_scan, mock_trigger_sbom_extraction

def security_scan_node(state: SecurityScanAgentState):
    """Sub-graph node for scanning, formatting actionable reports, and triggering SBOM."""
    pass
### 6.3. model/llm_setup.py (Model Initialization)
```python
import os
from langchain_google_genai import ChatGoogleGenerativeAI

def get_gemini_llm(model_name: str = "gemini-1.5-pro", temperature: float = 0):
    """
    Initializes and returns the Gemini LLM instance.
    Ensure 'GEMINI_API_KEY' is set in the environment variables.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")
    
    llm = ChatGoogleGenerativeAI(
        model=model_name,
        temperature=temperature,
        google_api_key=api_key
    )
    return llm
### 6.4. graph.py (Graph Definition)
```python
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from states.state import SecurityAgentState
from nodes.init_node import init_context_node
from nodes.supervisor_node import supervisor_node
from nodes.repo_agent_node import repo_agent_node
from nodes.packaging_agent_node import packaging_agent_node
from nodes.security_scan_node import security_scan_node

def build_agent_graph():
    """Builds and compiles the Security Agent LangGraph."""
    workflow = StateGraph(SecurityAgentState)
    
    workflow.add_node("init_node", init_context_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("RepoAgent", repo_agent_node)
    workflow.add_node("PackagingAgent", packaging_agent_node)
    workflow.add_node("SecurityScanAgent", security_scan_node)
    
    workflow.set_entry_point("init_node")
    workflow.add_edge("init_node", "supervisor")
    
    workflow.add_conditional_edges(
        "supervisor",
        lambda state: state.get("next_agent"),
        {
            "RepoAgent": "RepoAgent",
            "PackagingAgent": "PackagingAgent",
            "SecurityScanAgent": "SecurityScanAgent"
        }
    )
    
    workflow.add_edge("RepoAgent", END)
    workflow.add_edge("PackagingAgent", END)
    workflow.add_edge("SecurityScanAgent", END)
    
    checkpointer = MemorySaver()
    return workflow.compile(checkpointer=checkpointer)

agent_app = build_agent_graph()

## 7. Advanced Implementation Constraints (CRITICAL FOR CLAUDE)
When writing the actual Python code, you MUST adhere to the following advanced constraints.

### 7.1. Multi-turn Continuous Conversation (Loop)
Requirement: The user must be able to continue issuing commands in the same session (e.g., "Now scan that package") after a task finishes.

Implementation: When PackagingAgent or SecurityScanAgent successfully completes its task, it MUST append an AI message explicitly asking: "작업이 완료되었습니다. 더 필요하신 것이 있나요?" (Task completed. Is there anything else you need?) before routing to END. The checkpointer will seamlessly route the next user input back through the supervisor.

### 7.2. State Initialization on Completion (State Reset)
Requirement: To prevent state contamination during multi-turn loops, Sub-Agents must clear their specific states before finishing.

Implementation: Just before a Sub-Agent transitions to END, it MUST return a state update that sets next_agent and all agent-specific variables (e.g., repo_name, package_name, approval_context) to None.

### 7.3. Strict Routing via Structured Output
Requirement: The supervisor_node must never output conversational text or hallucinate agent names.

Implementation: You MUST use LangChain's .with_structured_output() feature paired with a Pydantic model (Literal["RepoAgent", "PackagingAgent", "SecurityScanAgent"]) for the Supervisor's LLM call.

### 7.4. Human-in-the-Loop using LangGraph interrupt()
Requirement: The RepoAgent must pause execution to get user confirmation for the approval line without complex conditional edge loops.

Implementation: You MUST use the latest LangGraph interrupt() API (langgraph.types.interrupt) to handle the HITL logic.

### 7.5. Tool Error Handling & Retry Loop
Requirement: If a tool execution fails due to business validation (e.g., mock_validate_package_name returns a "Duplicate Name" error), the Agent must NOT terminate.

Implementation: The Sub-Agent must catch this business error, prompt for a correction (e.g., "패키지 이름이 중복됩니다. 다른 이름을 알려주세요."), and use interrupt() to explicitly wait for the corrected value from the user. It should then update the state and retry the tool execution.

### 7.6. CLI Loop with Command Resume (main.py)
Requirement: The execution loop in main.py must correctly detect when the graph is paused by an interrupt() and resume it properly using LangGraph's Command object.

Implementation:

```python
import uuid
from langgraph.types import Command
from graph import agent_app

def main():
    print("Initializing DevSecOps Security Agent...")
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    mock_jwt = {"user_id": "test_user_01", "roles": ["developer"]}
    
    print(f"Session started. (Thread ID: {thread_id})\nType 'quit' or 'exit' to terminate.\n")
    
    while True:
        user_input = input("User: ")
        if user_input.lower() in ['quit', 'exit']: break
            
        state = agent_app.get_state(config)
        
        if state.next:
            # Graph is paused (e.g., waiting for HITL approval or retry input)
            stream = agent_app.stream(Command(resume=user_input), config)
        else:
            # Normal new invocation
            initial_state = {"messages": [("user", user_input)], "jwt_claims": mock_jwt}
            stream = agent_app.stream(initial_state, config)
            
        for output in stream:
            for node_name, state_update in output.items():
                print(f"--- Node '{node_name}' Executed ---")

if __name__ == "__main__":
    main()    



이제 동작 순서는 다음과 같습니다.

사용자가 "외부 저장소 추가하고 싶어"라고 요청

바로 승인 라인을 묻지 않고 다음을 질문

추가할 사외 저장소 URL을 알려주세요.

URL 입력

Mock 백엔드가 URL 기반으로 저장소 이름 자동 생성

예: https://registry.example.com/team/public-repository
자동 이름: public-repository
생성된 저장소 이름과 함께 승인 라인 확인 요청

사용자가 승인하면 티켓 생성

추가된 Mock 백엔드 로직:

mock_name_external_repo()
HTTP/HTTPS URL 검증
URL path 기반 저장소 이름 자동 생성
path가 없으면 호스트명 기반 이름 생성
잘못된 URL이면 다시 URL 입력 요청