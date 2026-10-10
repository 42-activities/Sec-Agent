"""Structured contracts passed between graph nodes.

Design rule: nodes communicate with Pydantic models, not free-form text, so the
security boundary reasons over structure instead of re-parsing prose.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, TypedDict

from pydantic import BaseModel, Field


class Trust(str, Enum):
    """How much we trust the *source* of a piece of context."""

    TRUSTED = "trusted"      # the user, or first-party system state
    INTERNAL = "internal"    # internal systems, still not user-authored
    UNTRUSTED = "untrusted"  # documents, webpages, RAG, MCP output, other agents


class Taint(str, Enum):
    """Propagated influence label — does untrusted data flow into this?"""

    NONE = "none"
    EXTERNAL = "external"
    SUSPICIOUS = "suspicious"  # external AND looks like it carries instructions


class ContextItem(BaseModel):
    """One piece of information available to the agent, with provenance."""

    id: str
    source: str
    source_type: str  # user_message | document | webpage | rag | mcp_output | memory
    content: str
    trust: Trust = Trust.UNTRUSTED
    taint: Taint = Taint.NONE
    instruction_detected: bool = False
    risk: float = Field(default=0.0, ge=0.0, le=1.0)


class ProposedAction(BaseModel):
    """What the executor wants to do. It is a *request*, never an execution."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(description="Why this action serves the user's goal.")
    source_ids: list[str] = Field(
        default_factory=list,
        description="IDs of the ContextItems that motivated this action.",
    )
    original_goal: str


class Decision(str, Enum):
    ALLOW = "ALLOW"
    APPROVAL = "APPROVAL"  # escalate to a human
    DENY = "DENY"

    @property
    def rank(self) -> int:
        """Higher == more restrictive. Used to combine decisions."""
        return {"ALLOW": 0, "APPROVAL": 1, "DENY": 2}[self.value]


def most_restrictive(*decisions: Decision) -> Decision:
    """Combine decisions by taking the most restrictive one."""
    return max(decisions, key=lambda d: d.rank)


class SecurityDecision(BaseModel):
    """Advisory verdict from the Output Security Agent (the security LLM).

    Advisory only — the deterministic policy engine can override it.
    """

    classification: str = Field(
        description="e.g. benign, indirect_prompt_injection, goal_hijacking, exfiltration",
    )
    risk_score: int = Field(ge=0, le=100)
    goal_relevance: float = Field(
        ge=0.0, le=1.0, description="How well the action matches the original goal."
    )
    decision: Decision
    reason: str


class AgentState(TypedDict, total=False):
    """Mutable state threaded through the LangGraph graph."""

    user_goal: str
    context_items: list[ContextItem]
    proposed_action: Optional[ProposedAction]
    security_decision: Optional[SecurityDecision]
    policy_decision: Optional[Decision]
    policy_reasons: list[str]
    final_decision: Optional[Decision]
    jev_input: dict  # context-item id -> Jev prompt-injection risk result
    execution_result: Optional[str]
    audit: list[str]
