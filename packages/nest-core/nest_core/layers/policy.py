# SPDX-License-Identifier: Apache-2.0
"""Policy layer interface: govern what an agent is allowed to do.

The policy layer is the decision authority for agent behaviour: given an agent, a
governed operation, and its arguments, it returns whether the action is permitted
by that agent's policy. It is the missing block the other twelve never covered —
identity says *who*, auth says *what scope a token carries*, but nothing said
*does this specific action stay within what the agent declared* (which tools it
may call, how much it may spend, what data it may expose, what needs prior
authorization).

A policy layer plugin is a Policy Decision Point. An enforcement proxy (the
reference :class:`~nest_plugins_reference.policy.enforcer.PolicyEnforcer`) wraps
the other layers' plugins and consults this one before each governed call,
blocking out-of-policy actions at runtime.

Example::

    class MyPolicy(Policy):
        async def authorize(self, agent, op, args):
            return PolicyDecision(allowed=True)
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from nest_core.types import AgentId, PolicyDecision


@runtime_checkable
class Policy(Protocol):
    """Authorize governed agent actions against the agent's policy.

    Example::

        policy: Policy = AllowAllPolicy()
        decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
    """

    async def authorize(self, agent: AgentId, op: str, args: dict[str, Any]) -> PolicyDecision:
        """Decide whether *agent* may perform *op* with *args*.

        Example::

            decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
            if not decision.allowed:
                raise RuntimeError(decision.reason)
        """
        ...

    def record_success(self, agent: AgentId, op: str, args: dict[str, Any]) -> None:
        """Update policy state after *agent* successfully performed *op*.

        Lets a stateful policy track cumulative effects (e.g. spend) and consume
        one-shot grants. A stateless policy may treat this as a no-op.

        Example::

            policy.record_success(AgentId("a1"), "pay", {"amount": 10})
        """
        ...
