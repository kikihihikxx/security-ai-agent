"""LangGraph based Security Agent."""

from .graph import agent_app, build_agent_graph

__all__ = ["agent_app", "build_agent_graph"]


def main() -> None:
    from .main import main as run_cli

    run_cli()
