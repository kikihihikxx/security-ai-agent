
# Security Agent LangGraph State & Architecture Specification (v2.0)

## 1. Domain & Business Logic Rules
* **Hierarchy:** `Product Group` -> `Internal Repo` -> `Package`. (External Proxy Repos are standalone and globally available).
* **Authorization:** User accessible `Product Groups`, `Products`, and `Packages` are strictly validated via Backend APIs using the user's JWT ID.
* **Approval Requirement:** BOTH External Proxy Repos and Internal Hosted Repos require explicit approval lines and user confirmation.
* **Packaging Lifecycle:** 
  * **Creation:** Requires selecting a Repo, specifying a Package Name (with duplicate check), Build Tool & Version, and Git Info (URL, Branch, Path).
  * **Execution (Build):** Once created, only the `Package Name` is required since Git info is managed by SDEP.
* **Security Scanning:** Can target either an SDEP `Package` or an external DevOps `Product`.

---

## 2. Graph State Definition (Decoupled Architecture)

To prevent the Global State from becoming bloated, we separate the state into a **Common Base State** (used by the Supervisor) and **Agent-Specific States** (used by each Sub-graph). 

Each Sub-Agent inherits the common fields (like `messages` and `jwt_claims`) while maintaining its own specific context.

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

### 3.1. Initialization / Context Node (Pre-routing)
* **Action:** Before routing, the Agent extracts the User ID from `jwt_claims` and calls the Product Group API.
* **Mock Tool:** `mock_get_accessible_product_groups(user_id)`
* **Effect:** Updates `accessible_product_groups` in the State so the Supervisor and Sub-Agents know exactly what the user is allowed to access.

### 3.2. Repo Agent (Handles Internal & External)
* **Workflow:**
  1. NLU identifies if the user wants an internal or external repo.
  2. If internal, validates if the requested product group is in `accessible_product_groups`.
  3. Calls `mock_get_approval_line(repo_type, product_group)` to fetch the required approvers.
  4. Saves to `approval_line` and **[Interrupts]** to ask the user: *"Here is the approval line. Proceed? (Yes/No)"*.
  5. On "Yes", calls `mock_request_repo_creation(repo_data, approval_line)` and returns the Ticket ID.

### 3.3. Packaging Agent
* **Workflow (Create Package):**
  1. Collects required fields (Repo, Name, Build Tool/Version, Git Info).
  2. Calls `mock_validate_package_name(package_name, repo_name)` to check for duplicates.
  3. Calls `mock_create_package_baseline(package_data)` to register the package in SDEP.
* **Workflow (Build Package):**
  1. User requests a build (e.g., "Build the payment-pkg").
  2. Agent calls `mock_trigger_build(package_name)`. (Git info is automatically handled by SDEP B/E).

### 3.4. Security Scan Agent
* **Workflow:**
  1. Determines if the target is an SDEP Package or a DevOps Product.
  2. Validates user permission using `mock_get_accessible_packages()` or `mock_get_accessible_products()`.
  3. Triggers scan via `mock_run_security_scan(target_type, target_name)`.
  4. Formats raw results into **Actionable Reports** (e.g., "Update dependency X to version Y", "Secret exposed on line Z").
  5. Strictly calls `mock_trigger_sbom_extraction(scan_id)` asynchronously after reporting.

---

## 4. Claude Implementation Guide
1. **LangGraph Setup:** Use the provided `SecurityAgentState` as the single source of truth for the `StateGraph`.
2. **Conditional Routing:** Implement `tools_condition` or custom routing logic in the Supervisor Node.
3. **Checkpointer:** Use `MemorySaver()` specifically for the Repo Agent's approval confirmation step to pause and resume the graph.
4. **Mock Tools:** Implement standard Python functions wrapped with `@tool` for all APIs mentioned above to simulate the SDEP platform and backend behaviors.

## 5. Directory Structure & File Split Architecture

Based on the decoupled State design, the project structure is split into specific `nodes/` and `prompts/` directories. Each Sub-Agent will have its own node implementation and prompt definition.

### Directory Tree
```text
security_agent/
├── __init__.py
├── main.py                     # Entry point (Application execution / CLI loop)
├── graph.py                    # LangGraph build, routing, and compilation logic
├── model/
│   ├── __init__.py
│   └── llm_setup.py            # Gemini LLM initialization
├── states/
│   ├── __init__.py
│   └── state.py                    # Contains SecurityAgentState and all Sub-States
├── prompts/
│   ├── __init__.py
│   ├── supervisor_prompt.py        # System prompt for Supervisor routing
│   ├── repo_agent_prompt.py        # System prompt for Repo creation & approval
│   ├── packaging_agent_prompt.py   # System prompt for Package baseline & build
│   └── security_scan_prompt.py     # System prompt for SCA/Secret scan & actionable reports
├── nodes/
│   ├── __init__.py
│   ├── init_node.py                # Pre-routing context node (fetches accessible groups)
│   ├── supervisor_node.py          # LLM router node
│   ├── repo_agent_node.py          # Repo sub-graph nodes (Approval HITL logic)
│   ├── packaging_agent_node.py     # Packaging sub-graph nodes
│   └── security_scan_node.py       # Security scan sub-graph nodes
└── tools/
│   ├── __init__.py
    └── mock_mcp_tools.py           # Mock implementations of SDEP & DevOps APIs


## 6. Detailed File Specifications (For Claude)

### 6.1. `prompts/` Files

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

**`prompts/repo_agent_prompt.py`**
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

**`prompts/packaging_agent_prompt.py`**
```python
PACKAGING_AGENT_SYSTEM_PROMPT = """You are the Packaging Agent for the SDEP platform.
You handle two distinct actions: 'create' (baseline) and 'build'.

For 'create': You must gather the target repo, package name, build tool & version, git URL, git branch, and manifest path.
For 'build': You only need the package name to trigger the build.

Always validate package names for duplicates using the provided tool before creating a baseline.
"""
**`prompts/security_scan_prompt.py`**
```python
SECURITY_SCAN_SYSTEM_PROMPT = """You are the Security Scanning Agent.
You handle Secret scans and SCA (Open Source Vulnerabilities) for SDEP Packages or External DevOps Products.

STRICT REPORTING RULES:
1. Your final response MUST be an Actionable Report. Do not just list CVEs. 
   - Good: "Update 'log4j' to version 2.17.1 to fix CVE-YYYY-XXXX."
   - Good: "AWS Access Key exposed in 'config/settings.yml' on line 42."
2. Never block the pipeline yourself.
3. After generating the report, you MUST call the tool to asynchronously trigger SBOM extraction for the backend.
"""

### 6.2. `nodes/` Files
**`nodes/init_node.py`**
```python
from states.state import SecurityAgentState
from tools.mock_mcp_tools import mock_get_accessible_product_groups

def init_context_node(state: SecurityAgentState):
    """Extracts User ID from JWT and populates accessible product groups before routing."""
    user_id = state.get("jwt_claims", {}).get("user_id")
    groups = mock_get_accessible_product_groups(user_id)
    return {"accessible_product_groups": groups}

**`nodes/supervisor_node.py`**
```python
from states.state import SecurityAgentState
from prompts.supervisor_prompt import SUPERVISOR_SYSTEM_PROMPT
# Import LLM...

def supervisor_node(state: SecurityAgentState):
    """Uses LLM with structured output to determine the 'next_agent'."""
    # LLM logic bound with SUPERVISOR_SYSTEM_PROMPT
    # Returns {"next_agent": "RepoAgent" | "PackagingAgent" | "SecurityScanAgent"}
    pass

**`nodes/repo_agent_node.py`**
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

**`nodes/packaging_agent_node.py`**
```python
from states.state import PackagingAgentState
from prompts.packaging_agent_prompt import PACKAGING_AGENT_SYSTEM_PROMPT
from tools.mock_mcp_tools import mock_validate_package_name, mock_create_package_baseline, mock_trigger_build

def packaging_agent_node(state: PackagingAgentState):
    """Sub-graph node for handling package baseline creation and build triggers."""
    pass

**`nodes/security_scan_node.py`**
```python
from states.state import SecurityScanAgentState
from prompts.security_scan_prompt import SECURITY_SCAN_SYSTEM_PROMPT
from tools.mock_mcp_tools import mock_run_security_scan, mock_trigger_sbom_extraction

def security_scan_node(state: SecurityScanAgentState):
    """Sub-graph node for scanning, formatting actionable reports, and triggering SBOM."""
    pass

### 7.1. Graph Definition (graph.py)
This file is solely responsible for building the StateGraph, defining the nodes, edges, conditional routing, and compiling the app with the checkpointer.
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
    # 1. Initialize Graph with Base State
    workflow = StateGraph(SecurityAgentState)
    
    # 2. Add Nodes
    workflow.add_node("init_node", init_context_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("RepoAgent", repo_agent_node)
    workflow.add_node("PackagingAgent", packaging_agent_node)
    workflow.add_node("SecurityScanAgent", security_scan_node)
    
    # 3. Define Edges & Routing
    workflow.set_entry_point("init_node")
    workflow.add_edge("init_node", "supervisor")
    
    # Conditional edge based on the 'next_agent' field set by the supervisor
    workflow.add_conditional_edges(
        "supervisor",
        lambda state: state.get("next_agent"),
        {
            "RepoAgent": "RepoAgent",
            "PackagingAgent": "PackagingAgent",
            "SecurityScanAgent": "SecurityScanAgent"
        }
    )
    
    # End edges for sub-agents
    workflow.add_edge("RepoAgent", END)
    workflow.add_edge("PackagingAgent", END)
    workflow.add_edge("SecurityScanAgent", END)
    
    # 4. Compile with Checkpointer (Required for HITL approval confirmation)
    checkpointer = MemorySaver()
    return workflow.compile(checkpointer=checkpointer)

# Export the compiled app instance
agent_app = build_agent_graph()

### 7.2. Application Entry Point (main.py)
This file imports the compiled graph and serves as the execution entry point. It sets up the execution context (like Thread ID for memory) and runs a simple loop for testing.
```python
import uuid
from graph import agent_app

def main():
    print("Initializing DevSecOps Security Agent...")
    
    # Mock JWT claims for local testing
    mock_jwt_claims = {
        "user_id": "test_user_01",
        "roles": ["developer"],
        "department": "platform_engineering"
    }
    
    # Generate a unique thread ID to maintain state across the session (critical for HITL)
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    
    print(f"Session started. (Thread ID: {thread_id})")
    print("Type 'quit' or 'exit' to terminate.\n")
    
    while True:
        user_input = input("User: ")
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Exiting Security Agent.")
            break
            
        # Prepare the initial state
        # Note: In a real environment, jwt_claims would be extracted from the incoming request token
        initial_state = {
            "messages": [("user", user_input)],
            "jwt_claims": mock_jwt_claims
        }
        
        # Stream the graph execution to see the node transitions
        print("\n[Agent Thinking...]")
        for output in agent_app.stream(initial_state, config):
            for node_name, state_update in output.items():
                print(f"--- Node '{node_name}' Executed ---")
                # Optionally print relevant state updates here
                # print(state_update)
        print("\n")

if __name__ == "__main__":
    main()

### 8.1. Model Setup (model/llm_setup.py)
This file handles the initialization of the Gemini model using langchain-google-genai. It ensures that the API key is securely loaded from environment variables and provides a singleton-like factory function for the nodes to use.
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
        raise ValueError("GEMINI_API_KEY environment variable is not set. Please set it before running the agent.")
    
    llm = ChatGoogleGenerativeAI(
        model=model_name,
        temperature=temperature,
        google_api_key=api_key
    )
    return llm

## 9. Business Logic & Process Guidelines (For Claude)

This section contains critical business rules, domain context, and process logic explained by the user. You must strictly adhere to these guidelines when implementing the Nodes, Prompts, and State logic.

### 9.1. SDEP Domain Architecture & Hierarchy
The DevSecOps platform (SDEP) follows a strict logical hierarchy:
1. **Product Group:** The highest logical group. A user can belong to multiple groups.
2. **Internal Repo:** Created *under* a specific Product Group.
3. **Package:** Created *under* a specific Internal Repo.
4. **External Proxy Repo:** Standalone. Not tied to a Product Group. Available to all developers across the company.
5. **Security Scan Targets:** Can be either an internal `Package` (from SDEP) or an external `Product` (from an external DevOps platform). Both ultimately belong to a `Product Group`.

### 9.2. Authorization & Context Flow
* **No Hallucinated Permissions:** Do not assume a user has access to a repo or package.
* **Init Node Enforcement:** The `init_node` uses the User ID from the `jwt_claims` to fetch `accessible_product_groups` via a mock B/E API. 
* **Validation:** All Sub-Agents MUST validate the user's request against this `accessible_product_groups` list (or accessible packages/products list) before executing any action.

### 9.3. Human-in-the-Loop (HITL) Approval Logic
Both Internal Hosted Repos and External Proxy Repos **REQUIRE** an approval process.
* **Process Flow:**
  1. Agent identifies the target repo specifications.
  2. Agent calls the API to fetch the designated `approval_line`.
  3. **Interrupt:** The Agent must display the approval line to the user and ask, *"Do you want to proceed with this approval line?"*
  4. Execution halts here using LangGraph's `MemorySaver` (Checkpointer).
  5. **Resume:** Only when the user inputs a confirmation (e.g., "Yes", "Proceed"), the Agent resumes the graph and calls the API to actually create the approval ticket.

### 9.4. Packaging Lifecycle Separation
The `PackagingAgent` handles two distinctly different operations. Your prompts and tool logic must distinguish between them:
1. **Create Package (Baseline Registration):**
   * **Required Input:** Target Repo, Package Name, Build Tool, Build Tool Version, Git URL, Git Branch, Manifest/Folder Path.
   * **Validation:** Must check if the Package Name is duplicated within the target repo before creation.
   * **Result:** Saves the baseline in the SDEP B/E. Does *not* trigger a build.
2. **Build Package (Execution):**
   * **Required Input:** Only the `Package Name`.
   * **Logic:** The SDEP B/E already knows the Git info from the baseline. The Agent just triggers the build pipeline and polls/returns the status.

### 9.5. Security Scanning Rules
The `SecurityScanAgent` has strict operational rules to ensure developer productivity:
1. **Non-Blocking:** The Agent must NEVER block or fail the CI/CD pipeline due to found vulnerabilities.
2. **Actionable Reporting:** Raw CVE lists are forbidden. The LLM must format the raw tool output into developer-friendly actionable items.
   * *Example:* "Update `spring-boot` to v3.1.2 in your `pom.xml` to resolve CVE-2023-XXXX."
3. **Asynchronous SBOM:** The Agent's job ends at reporting. However, immediately after providing the report, it MUST call the mock tool to trigger the Backend SBOM extraction process asynchronously.

### 9.6. Mock MCP Tool Usage
* You are building the LangGraph agent *before* the actual MCP server is ready.
* Implement all necessary DevSecOps API interactions as standard LangChain `@tool` functions (Mock Tools).
* Return hardcoded but realistic JSON/Dictionary responses from these mock tools so the LLM can properly parse and format the data.


## 10. Advanced Implementation Constraints (CRITICAL FOR CLAUDE)

When writing the actual Python code for the LangGraph application, you MUST adhere to the following advanced implementation constraints.

### 10.1. Multi-turn Continuous Conversation (Loop)
* **Requirement:** The user must be able to continue issuing commands in the same session (e.g., "Now scan that package") after a task finishes.
* **Implementation:** 
  1. When `PackagingAgent` or `SecurityScanAgent` successfully completes its task, it MUST append an AI message to the `messages` state explicitly asking: *"작업이 완료되었습니다. 더 필요하신 것이 있나요?"* (Task completed. Is there anything else you need?).
  2. The graph can then route to `END`. Because we use a `MemorySaver` checkpointer with a consistent `thread_id`, the next user input will naturally trigger the graph from the entry point (`init_node` -> `supervisor`) with the full conversation history preserved, enabling a seamless multi-turn loop.

### 10.2. Strict Routing via Structured Output
* **Requirement:** The `supervisor_node` must never output conversational text or hallucinate agent names. It must strictly return the exact designated agent name.
* **Implementation:** You MUST use LangChain's `.with_structured_output()` feature paired with a Pydantic model for the Supervisor's LLM call.
  * *Example Concept:*
    ```python
    from pydantic import BaseModel, Field
    from typing import Literal

    class RouteDecision(BaseModel):
        next_agent: Literal["RepoAgent", "PackagingAgent", "SecurityScanAgent"] = Field(
            description="The next sub-agent to route the request to."
        )
    
    # In supervisor_node:
    # structured_llm = llm.with_structured_output(RouteDecision)
    ```

### 10.3. Human-in-the-Loop using LangGraph `interrupt()`
* **Requirement:** The `RepoAgent` must pause execution to get user confirmation for the approval line without using complex conditional edge loops.
* **Implementation:** You MUST use the latest LangGraph `interrupt()` API (available in `langgraph.types`) to handle the Human-in-the-Loop (HITL) logic.
  * *Workflow in `repo_agent_node`:* 
    1. Fetch the approval line.
    2. Display it and use `response = interrupt("결재선을 확인해주세요. 진행하시겠습니까? (Yes/No)")`.
    3. The graph will pause here. When resumed with the user's answer, evaluate `response` to either proceed with creating the ticket or abort the operation.


## 10. Advanced Implementation Constraints (CRITICAL FOR CLAUDE)

When writing the actual Python code for the LangGraph application, you MUST adhere to the following advanced implementation constraints.

### 10.1. Multi-turn Continuous Conversation (Loop)
* **Requirement:** The user must be able to continue issuing commands in the same session (e.g., "Now scan that package") after a task finishes.
* **Implementation:** 
  1. When `PackagingAgent` or `SecurityScanAgent` successfully completes its task, it MUST append an AI message to the `messages` state explicitly asking: *"작업이 완료되었습니다. 더 필요하신 것이 있나요?"* (Task completed. Is there anything else you need?).
  2. The graph can then route to `END`. Because we use a `MemorySaver` checkpointer with a consistent `thread_id`, the next user input will naturally trigger the graph from the entry point (`init_node` -> `supervisor`) with the full conversation history preserved, enabling a seamless multi-turn loop.

### 10.2. State Initialization on Completion (State Reset)
* **Requirement:** To prevent state contamination during multi-turn loops, Sub-Agents must clear their specific states before finishing.
* **Implementation:** Just before a Sub-Agent transitions to `END`, it MUST return a state update that sets `next_agent` and all agent-specific variables (e.g., `repo_name`, `package_name`, `approval_context`, `mcp_tool_results`) to `None`.

### 10.3. Strict Routing via Structured Output
* **Requirement:** The `supervisor_node` must never output conversational text or hallucinate agent names. It must strictly return the exact designated agent name.
* **Implementation:** You MUST use LangChain's `.with_structured_output()` feature paired with a Pydantic model for the Supervisor's LLM call.

### 10.4. Human-in-the-Loop using LangGraph `interrupt()`
* **Requirement:** The `RepoAgent` must pause execution to get user confirmation for the approval line without using complex conditional edge loops.
* **Implementation:** You MUST use the latest LangGraph `interrupt()` API (available in `langgraph.types`) to handle the Human-in-the-Loop (HITL) logic.

### 10.5. Tool Error Handling & Retry Loop
* **Requirement:** If a tool execution fails due to business validation (e.g., `mock_validate_package_name` returns a "Duplicate Name" error), the Agent must NOT terminate the workflow or route to `END`.
* **Implementation:** The Sub-Agent must catch this business error, explain it to the user, and prompt for a correction (e.g., *"패키지 이름이 중복됩니다. 다른 이름을 알려주세요."*). It should then use `interrupt()` to explicitly wait for the corrected value from the user, update the state with the new value, and retry the validation/tool execution.

### 10.6. CLI Loop with Command Resume (`main.py`)
* **Requirement:** The execution loop in `main.py` must correctly detect when the graph is paused by an `interrupt()` and resume it properly using LangGraph's `Command` object.
* **Implementation:** Use `app.get_state(config).next` to check if there are pending tasks (suspended nodes). If suspended, pass the user's input via `Command(resume=user_input)`.
* **Code Snippet Example (for `main.py`):**
  ```python
  from langgraph.types import Command
  
  # Inside the while True loop handling user_input:
  state = app.get_state(config)
  
  if state.next:
      # Graph is paused (e.g., waiting for HITL approval or retry input)
      # Resume the graph using Command
      for output in app.stream(Command(resume=user_input), config):
          for node_name, state_update in output.items():
              print(f"--- Node '{node_name}' Executed ---")
  else:
      # Normal new invocation
      # Note: Do not override the whole state, just append the new message
      initial_state = {"messages": [("user", user_input)]}
      for output in app.stream(initial_state, config):
          for node_name, state_update in output.items():
              print(f"--- Node '{node_name}' Executed ---")