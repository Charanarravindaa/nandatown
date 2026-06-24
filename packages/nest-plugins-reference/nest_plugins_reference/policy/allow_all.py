# SPDX-License-Identifier: Apache-2.0
"""Allow-all policy plugin — the harmless default for the policy layer.

Authorizes every governed action and records nothing. Selecting it (the
default) leaves a scenario behaving exactly as if no policy layer existed, so
every pre-existing scenario stays byte-identical.

Example::

    policy = AllowAllPolicy()
    decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
    assert decision.allowed
"""

from __future__ import annotations

from typing import Any

from nest_core.types import AgentId, PolicyDecision


class AllowAllPolicy:
    """Permit every action; never deny, never track state.

    Example::

        policy = AllowAllPolicy()
        assert (await policy.authorize(AgentId("a1"), "call_tool", {})).allowed
    """

    async def authorize(self, agent: AgentId, op: str, args: dict[str, Any]) -> PolicyDecision:
        """Allow *agent* to perform *op* unconditionally.

        Example::

            decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
            assert decision.allowed
        """
        return PolicyDecision(allowed=True)

    def record_success(self, agent: AgentId, op: str, args: dict[str, Any]) -> None:
        """No-op — the allow-all policy keeps no state.

        Example::

            policy.record_success(AgentId("a1"), "pay", {"amount": 10})
        """
