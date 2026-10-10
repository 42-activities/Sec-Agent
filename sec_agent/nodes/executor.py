"""Main Executor Agent.

Performs the user's task and emits a structured ProposedAction. It does NOT
execute anything. It is deliberately *not* hardened against injection — the whole
point of the project is that even a compromised executor cannot cause harm,
because the output-side controller gates every action.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from ..llm import make_executor_llm
from ..models import AgentState, ContextItem, ProposedAction

_SYSTEM = """You are a task-execution agent. You help the user by choosing ONE tool call.

Available tools (you may only use these):
- read_document(path): read an uploaded document
- read_file(path): read a file from disk
- write_file(path, content): write a file
- send_email(recipient, body): send an email
- http_request(method, url, body): make an HTTP request

You never execute actions yourself — you only PROPOSE one action as structured
output. Always fill `original_goal` with the user's actual request, `source_ids`
with the IDs of the context items that led to your choice, and `reason` with a
short justification.
"""


def _render_context(items: list[ContextItem]) -> str:
    blocks = []
    for i in items:
        blocks.append(
            f"<context id={i.id} source={i.source} type={i.source_type} "
            f"trust={i.trust.value}>\n{i.content}\n</context>"
        )
    return "\n\n".join(blocks) if blocks else "(no additional context)"


def executor_node(state: AgentState) -> AgentState:
    llm = make_executor_llm().with_structured_output(ProposedAction)
    items = state.get("context_items", [])
    goal = state["user_goal"]

    prompt = (
        f"User goal: {goal}\n\n"
        f"Context available to you:\n{_render_context(items)}\n\n"
        f"Propose the single most appropriate tool action."
    )
    action: ProposedAction = llm.invoke(
        [SystemMessage(content=_SYSTEM), HumanMessage(content=prompt)]
    )
    # Guarantee the original goal is recorded even if the model omits it.
    if not action.original_goal:
        action.original_goal = goal

    audit = list(state.get("audit", []))
    audit.append(
        f"[executor] proposed {action.tool}(args={action.arguments}) "
        f"source_ids={action.source_ids}"
    )
    return {"proposed_action": action, "audit": audit}
