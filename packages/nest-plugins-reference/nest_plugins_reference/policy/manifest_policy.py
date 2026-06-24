# SPDX-License-Identifier: Apache-2.0
"""Manifest-backed policy plugin — the real Policy Decision Point for the layer.

This is the load-bearing implementation of the :class:`~nest_core.layers.policy.Policy`
protocol. It holds each agent's verified
:class:`~nest_plugins_reference.policy.manifest.PolicyManifest` plus a per-agent
:class:`~nest_plugins_reference.policy.decide.PolicyState`, and answers
:meth:`authorize` by running the shared :func:`~nest_plugins_reference.policy.decide.decide`
core for that agent's manifest. An agent with no registered manifest is governed
by a deny-all manifest, so it can do nothing.

The enforcement proxy (:class:`~nest_plugins_reference.policy.enforcer.PolicyEnforcer`)
consults this PDP before each governed call and calls :meth:`record_success`
afterwards so cumulative spend and single-use approvals are tracked here, not in
the enforcer.

Example::

    policy = ManifestPolicy({AgentId("a1"): manifest})
    decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
    if decision.allowed:
        policy.record_success(AgentId("a1"), "pay", {"amount": 10})
"""

from __future__ import annotations

from typing import Any

from nest_core.types import AgentId, PolicyDecision

from nest_plugins_reference.policy.decide import (
    PolicyState,
    approval_key,
    decide,
)
from nest_plugins_reference.policy.manifest import PolicyManifest


class ManifestPolicy:
    """Per-agent manifest-backed Policy Decision Point.

    Holds the verified manifests and per-agent :class:`PolicyState`; an unknown
    agent falls back to a deny-all :class:`PolicyManifest`. Reuses the shared
    :func:`decide` core so this PDP and ``policy_auth`` can never disagree.

    Example::

        policy = ManifestPolicy()
        policy.add_manifest(manifest)
        assert (await policy.authorize(manifest.agent_id, "pay", {"amount": 1})).allowed
    """

    def __init__(self, manifests: dict[AgentId, PolicyManifest] | None = None) -> None:
        self._manifests: dict[AgentId, PolicyManifest] = dict(manifests or {})
        self._states: dict[AgentId, PolicyState] = {}

    def state_for(self, agent: AgentId) -> PolicyState:
        """Return *agent*'s :class:`PolicyState`, creating it once on demand.

        The same object is returned on every call so a grant or recorded spend
        is visible to later :meth:`authorize` checks.

        Example::

            state = policy.state_for(AgentId("a1"))
        """
        state = self._states.get(agent)
        if state is None:
            state = PolicyState()
            self._states[agent] = state
        return state

    async def authorize(self, agent: AgentId, op: str, args: dict[str, Any]) -> PolicyDecision:
        """Decide whether *agent* may perform *op* with *args*.

        Runs the shared :func:`decide` core against *agent*'s manifest (deny-all
        when the agent has no registered manifest).

        Example::

            decision = await policy.authorize(AgentId("a1"), "pay", {"amount": 10})
        """
        manifest = self._manifests.get(agent)
        if manifest is None:
            manifest = PolicyManifest(agent_id=agent)
        decision = decide(manifest, op, args, self.state_for(agent))
        return PolicyDecision(allowed=decision.allowed, reason=decision.reason)

    def record_success(self, agent: AgentId, op: str, args: dict[str, Any]) -> None:
        """Record the effect of a successful governed *op* for *agent*.

        For ``pay`` this adds the spend (so the cap is cumulative) and consumes
        any single-use, amount-bound approval just used.

        Example::

            policy.record_success(AgentId("a1"), "pay", {"amount": 10})
        """
        if op != "pay":
            return
        # Record only what decide() would have accepted: reject bool/non-int
        # (no float-truncation) and default the currency to the manifest's budget
        # currency (matching decide), so the cumulative-cap invariant lives in the
        # policy core, not in the caller's discipline.
        raw = args.get("amount", 0)
        if isinstance(raw, bool) or not isinstance(raw, int):
            return
        manifest = self._manifests.get(agent)
        default_currency = manifest.budget.currency if manifest and manifest.budget else "credits"
        currency = str(args.get("currency", default_currency))
        state = self.state_for(agent)
        state.record_spend(currency, raw)
        state.approvals.discard(approval_key("pay", raw))

    def grant(self, agent: AgentId, op: str, amount: int) -> None:
        """Grant *agent* a single-use approval for *op* at *amount*.

        Example::

            policy.grant(AgentId("a1"), "pay", 500)
        """
        self.state_for(agent).grant(approval_key(op, amount))

    def add_manifest(self, manifest: PolicyManifest) -> None:
        """Register *manifest* as the policy governing ``manifest.agent_id``.

        Example::

            policy.add_manifest(manifest)
        """
        self._manifests[manifest.agent_id] = manifest
