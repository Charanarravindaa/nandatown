# SPDX-License-Identifier: Apache-2.0
"""PolicyEnforcer — the runtime enforcement surface (the real block).

This is the enforcement arm of the policy layer. It wraps a layer-plugin
instance for one agent and, before each governed call, consults the policy layer
(a :class:`~nest_core.layers.policy.Policy` Decision Point) via
:meth:`~nest_core.layers.policy.Policy.authorize`. An out-of-policy call
**raises** :class:`PolicyViolationError` so the underlying effect never happens —
money is not moved, data is not exposed to an audience, a capability is not
registered. In-policy calls delegate to the wrapped plugin and then report the
success back to the policy layer (which tracks cumulative spend and consumes
single-use approvals). Every other attribute is delegated unchanged, so the
proxy is a drop-in for the plugin.

The decision authority is the policy layer; the enforcer never decides on its
own. Keeping the policy in the layer (not the proxy) is what makes the layer
load-bearing rather than decorative.

Scope of the guarantee: the enforcer governs the plugin *handle the agent is
given*. Money moves only through the payments plugin, registry writes only
through the registry plugin, audience-scoped exposure only through the privacy
plugin — so for an agent that calls those governed APIs, wrapping them is
airtight and a buggy agent cannot exceed its signed policy. It does **not**
sandbox an in-process agent that reaches around the proxy (e.g. raw ``ctx.send``,
or poking ``._wrapped`` via Python internals); that is the same un-isolated-runtime
limitation documented in the project README. A production runtime isolates the
agent; here the boundary is the handle.

The reference simulator does not isolate a raising agent callback, so the
scenario's agents catch :class:`PolicyViolationError` (and the wrapped plugin's
own ``ValueError``s), exactly as a caller must handle a denied syscall. The
guarantee is that the *effect* is blocked regardless of the agent's intent.

Example::

    enf = PolicyEnforcer(AgentId("a1"), policy, payments)
    await enf.pay(AgentId("a2"), Money(amount=10), PaymentRef("p1"))  # in policy
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nest_core.types import AgentCard, AgentId, Money, PaymentRef, Receipt

from nest_plugins_reference.policy.decide import PolicyViolationError

if TYPE_CHECKING:
    from nest_core.layers.policy import Policy


class PolicyEnforcer:
    """Per-agent policy enforcement proxy over a single layer plugin.

    Wraps ``wrapped`` (e.g. a payments / registry / privacy plugin) and consults
    the shared policy layer (``policy``) before each governed call. The policy
    holds the per-agent state, so all of one agent's proxies share cumulative
    spend and approvals automatically.

    Example::

        enf = PolicyEnforcer(AgentId("a1"), policy, payments)
    """

    def __init__(
        self,
        agent_id: AgentId,
        policy: Policy,
        wrapped: Any,
        data_class: str = "default",
    ) -> None:
        self._agent_id = agent_id
        self._policy = policy
        self._wrapped = wrapped
        self._data_class = data_class

    def __getattr__(self, name: str) -> Any:
        # Delegate non-governed public attributes to the wrapped plugin. Names
        # with a leading underscore (the proxy's own internals, and dunders used
        # by copy/deepcopy/pickle) raise AttributeError so a partially-built
        # instance — created via __new__ without __init__, where ``_wrapped`` is
        # unset — cannot recurse infinitely through this method.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._wrapped, name)

    async def _check(self, op: str, args: dict[str, Any]) -> None:
        decision = await self._policy.authorize(self._agent_id, op, args)
        if not decision.allowed:
            raise PolicyViolationError(self._agent_id, op, decision.reason)

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Enforce the spend cap + approval gate, then delegate to the plugin.

        On success, reports the spend to the policy layer (so the cap is
        cumulative across calls) and lets it consume any single-use approval.

        Example::

            receipt = await enf.pay(AgentId("a2"), Money(amount=10), PaymentRef("p"))
        """
        await self._check("pay", {"amount": amount.amount, "currency": amount.currency})
        receipt = await self._wrapped.pay(to, amount, ref)
        self._policy.record_success(
            self._agent_id, "pay", {"amount": amount.amount, "currency": amount.currency}
        )
        return receipt

    async def register(self, card: AgentCard) -> None:
        """Enforce the capability allowlist, then delegate to the plugin.

        Example::

            await enf.register(card)
        """
        await self._check("register", {"capabilities": list(card.capabilities)})
        await self._wrapped.register(card)

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Enforce the data-exposure audience policy, then delegate to the plugin.

        Example::

            ct = await enf.encrypt(b"secret", [AgentId("a2")])
        """
        await self._check(
            "expose",
            {"data_class": self._data_class, "audience": [str(a) for a in audience]},
        )
        return await self._wrapped.encrypt(data, audience)
