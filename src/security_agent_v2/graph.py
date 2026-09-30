from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from security_agent_v2.nodes import (
    clarification_node,
    feature_discovery_node,
    intent_classifier_node,
    init_context_node,
    packaging_agent_node,
    repo_agent_node,
    route_after_classification,
    security_scan_node,
    support_guide_node,
    supervisor_node,
)
from security_agent_v2.states.state import SecurityAgentState


def build_agent_graph(
    checkpointer: BaseCheckpointSaver | None = None,
    *,
    use_memory_saver: bool = True,
):
    """Compile the Security Agent graph with the supplied checkpointer."""
    workflow = StateGraph(SecurityAgentState)
    workflow.add_node("init_node", init_context_node)
    workflow.add_node("intent_classifier", intent_classifier_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("RepoAgent", repo_agent_node)
    workflow.add_node("PackagingAgent", packaging_agent_node)
    workflow.add_node("SecurityScanAgent", security_scan_node)
    workflow.add_node("UnknownIntent", clarification_node)
    workflow.add_node("FeatureDiscovery", feature_discovery_node)
    workflow.add_node("SupportGuide", support_guide_node)

    workflow.add_edge(START, "intent_classifier")
    workflow.add_conditional_edges(
        "intent_classifier",
        route_after_classification,
        {
            "init_context": "init_node",
            "SupportGuide": "SupportGuide",
            "FeatureDiscovery": "FeatureDiscovery",
            "UnknownIntent": "UnknownIntent",
        },
    )
    workflow.add_edge("init_node", "supervisor")
    workflow.add_conditional_edges(
        "supervisor",
        lambda state: state.get("next_agent"),
        {
            "RepoAgent": "RepoAgent",
            "PackagingAgent": "PackagingAgent",
            "SecurityScanAgent": "SecurityScanAgent",
            "UnknownIntent": "UnknownIntent",
            "FeatureDiscovery": "FeatureDiscovery",
            "SupportGuide": "SupportGuide",
        },
    )
    workflow.add_edge("RepoAgent", END)
    workflow.add_edge("PackagingAgent", END)
    workflow.add_edge("SecurityScanAgent", END)
    workflow.add_edge("UnknownIntent", END)
    workflow.add_edge("FeatureDiscovery", END)
    workflow.add_edge("SupportGuide", END)
    saver = (
        checkpointer
        if checkpointer is not None
        else MemorySaver()
        if use_memory_saver
        else None
    )
    return workflow.compile(checkpointer=saver)


agent_app = build_agent_graph()
studio_app = build_agent_graph(use_memory_saver=False)