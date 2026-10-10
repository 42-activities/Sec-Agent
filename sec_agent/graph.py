"""LangGraph wiring.

    START -> input_guard -> executor -> security -> policy -> route:
                                                        ALLOW    -> execute
                                                        APPROVAL -> execute (human gate in proxy)
                                                        DENY     -> END
"""

from __future__ import annotations

from typing import Optional

from langgraph.graph import END, START, StateGraph

from .models import AgentState, Decision
from .nodes.executor import executor_node
from .nodes.input_guard import input_guard_node
from .nodes.policy import policy_node
from .nodes.security import security_node
from .proxy import ApprovalFn, execution_proxy_node


def _route_after_policy(state: AgentState) -> str:
    return "deny" if state.get("final_decision") == Decision.DENY else "execute"


def build_graph(
    approval_fn: Optional[ApprovalFn] = None,
    include_executor: bool = True,
    execute: bool = True,
    include_input_guard: bool = True,
):
    """Compile the security-controller graph.

    Args:
        approval_fn: handles the APPROVAL decision (defaults to fail-closed).
        include_executor: when False, the executor node is skipped and the graph
            runs the controller over a ``proposed_action`` already present in the
            initial state — used to demo a *compromised* executor deterministically.
        execute: when False, the graph ends after ``policy`` without invoking the
            execution proxy — used by the web API to stop for a human-approval gate
            and run the proxy separately once the human responds.
    """

    def _proxy(state: AgentState) -> AgentState:
        return execution_proxy_node(state, approval_fn=approval_fn)

    g = StateGraph(AgentState)
    g.add_node("security", security_node)
    g.add_node("policy", policy_node)

    # include_input_guard=False: the caller already ran it (e.g. a human reviewed flagged inputs).
    first = START
    if include_input_guard:
        g.add_node("input_guard", input_guard_node)
        g.add_edge(START, "input_guard")
        first = "input_guard"
    if include_executor:
        g.add_node("executor", executor_node)
        g.add_edge(first, "executor")
        g.add_edge("executor", "security")
    else:
        g.add_edge(first, "security")
    g.add_edge("security", "policy")

    if execute:
        g.add_node("execute", _proxy)
        g.add_conditional_edges(
            "policy", _route_after_policy, {"execute": "execute", "deny": END}
        )
        g.add_edge("execute", END)
    else:
        g.add_edge("policy", END)
    return g.compile()
