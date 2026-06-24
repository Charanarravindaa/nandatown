# SPDX-License-Identifier: Apache-2.0
"""Policy-governance scenario — identity-bound policy enforcement, on/off by a toggle.

Every actor carries an owner-authored, Ed25519-signed
:class:`~nest_plugins_reference.policy.manifest.PolicyManifest` bounding four
governance dimensions: which tools/capabilities it may register, what data it may
expose (and to whom), how much it may spend, and which spends need prior
authorization. A coordinator grants the one approved spend and drives the round.

Each actor runs a fixed *action plan* through its (possibly proxied) layer
plugins. Honest plans stay within policy; byzantine plans violate every
dimension; a forged-manifest agent's manifest fails signature verification, so it
is governed by a deny-all policy. After a governed call **succeeds** the actor
emits an ``action:`` audit line; when a call is **blocked** it catches the
:class:`PolicyViolationError` and emits ``policy_denied:`` — exactly how a caller
must handle a denied syscall (the reference simulator does not isolate a raising
callback). Manifests are announced (with the signer's public key) so the
validators can verify signatures offline.

The single ``enforcement`` config toggle is the whole experiment:

* ``enforced`` (default) wraps each agent's plugins in a
  :class:`~nest_plugins_reference.policy.enforcer.PolicyEnforcer` (one shared
  :class:`PolicyState` per agent) — byzantine attempts are blocked, so the trace
  contains no successful violation.
* ``permissive`` hands agents the raw plugins — the same byzantine attempts
  succeed and appear as ``action:`` lines.

The ``policy_governance`` validators flip every verdict on that one toggle.

Example::

    agents = policy_governance_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Money, PaymentRef

_COORDINATOR = AgentId("coordinator-0")
_HONEST_BASIC = AgentId("honest-0")
_HONEST_APPROVED = AgentId("honest-1")
_BYZANTINE = AgentId("byzantine-0")
_FORGED = AgentId("forged-0")
_ACTORS = [_HONEST_BASIC, _HONEST_APPROVED, _BYZANTINE, _FORGED]

# The approved spend the coordinator authorises for honest-1 (over threshold).
_APPROVED_AMOUNT = 80

# Per-actor action plans. Honest plans stay in policy; byzantine plans violate
# each dimension; the forged agent attempts an otherwise-fine register that its
# deny-all manifest blocks.
_PLANS: dict[AgentId, list[dict[str, Any]]] = {
    _HONEST_BASIC: [
        {"op": "register", "capabilities": ["sell"]},
        {"op": "pay", "to": "coordinator-0", "amount": 40, "currency": "credits"},
        {"op": "expose", "data_class": "default", "audience": ["coordinator-0"]},
    ],
    _HONEST_APPROVED: [
        {"op": "pay", "to": "coordinator-0", "amount": _APPROVED_AMOUNT, "currency": "credits"},
    ],
    _BYZANTINE: [
        {"op": "register", "capabilities": ["sell", "admin"]},  # forbidden capability
        {"op": "pay", "to": "coordinator-0", "amount": 200, "currency": "credits"},  # over cap
        {"op": "expose", "data_class": "default", "audience": ["evil-corp"]},  # bad audience
        {"op": "pay", "to": "coordinator-0", "amount": 80, "currency": "credits"},  # no approval
    ],
    _FORGED: [
        {"op": "register", "capabilities": ["sell"]},  # blocked by deny-all policy
    ],
}


class GovernedActor(StateMachineAgent):
    """Announces its signed manifest, then runs an action plan through its plugins.

    Emits ``action:`` after a successful governed call and ``policy_denied:`` when
    a call is blocked. Identical code for honest, byzantine, and forged agents —
    only the manifest and plan differ.

    Example::

        actor = GovernedActor(AgentId("honest-0"), AgentId("coordinator-0"), m, ident, plan)
    """

    def __init__(
        self,
        agent_id: AgentId,
        sink: AgentId,
        manifest: Any,
        identity: Any,
        plan: list[dict[str, Any]],
    ) -> None:
        self._id = agent_id
        self._sink = sink
        self._manifest = manifest
        self._identity = identity
        self._plan = plan
        self._pay_idx = 0

    async def _emit(self, ctx: AgentContext, kind: str, body: dict[str, Any]) -> None:
        line = kind + ":" + json.dumps(body, sort_keys=True)
        await ctx.send(self._sink, line.encode())

    async def on_start(self, ctx: AgentContext) -> None:
        """Announce this agent's signed manifest (with its public key).

        Example::

            await actor.on_start(ctx)
        """
        pubkey = self._identity.public_key.hex() if self._identity is not None else ""
        await self._emit(
            ctx,
            "manifest",
            {
                "agent": str(self._id),
                "manifest": self._manifest.model_dump(mode="json"),
                "pubkey": pubkey,
            },
        )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the coordinator's ``go:`` pulse, run the action plan.

        Example::

            await actor.on_message(ctx, coordinator, b"go:")
        """
        if payload.decode("utf-8", errors="replace").startswith("go:"):
            await self._run_plan(ctx)

    async def _run_plan(self, ctx: AgentContext) -> None:
        from nest_plugins_reference.policy.decide import PolicyViolationError

        for item in self._plan:
            detail = {k: v for k, v in item.items() if k != "op"}
            try:
                await self._do(ctx, item)
            except PolicyViolationError as exc:
                await self._emit(
                    ctx,
                    "policy_denied",
                    {"agent": str(self._id), "op": item["op"], "reason": exc.reason, **detail},
                )
            except ValueError as exc:
                await self._emit(
                    ctx,
                    "policy_denied",
                    {"agent": str(self._id), "op": item["op"], "reason": str(exc), **detail},
                )
            else:
                await self._emit(
                    ctx,
                    "action",
                    {"agent": str(self._id), "op": item["op"], **detail},
                )

    async def _do(self, ctx: AgentContext, item: dict[str, Any]) -> None:
        op = item["op"]
        if op == "register":
            registry: Any = ctx.plugins.get("registry")
            card = AgentCard(
                agent_id=self._id, name=str(self._id), capabilities=list(item["capabilities"])
            )
            await registry.register(card)
        elif op == "pay":
            payments: Any = ctx.plugins.get("payments")
            self._pay_idx += 1
            ref = PaymentRef(f"{self._id}-pay-{self._pay_idx}")
            amount = Money(amount=int(item["amount"]), currency=str(item["currency"]))
            await payments.pay(AgentId(str(item["to"])), amount, ref)
        elif op == "expose":
            privacy: Any = ctx.plugins.get("privacy")
            audience = [AgentId(str(a)) for a in item["audience"]]
            await privacy.encrypt(b"payload", audience)


class CoordinatorAgent(StateMachineAgent):
    """Grants the approved spend, announces it, and pulses actors to act.

    Also the audit sink: every actor sends its ``manifest:``/``action:``/
    ``policy_denied:`` lines here, so they land in the trace.

    Example::

        coord = CoordinatorAgent(AgentId("coordinator-0"), actors, grants, states)
    """

    def __init__(
        self,
        agent_id: AgentId,
        actors: list[AgentId],
        grants: list[tuple[AgentId, int]],
        states: dict[AgentId, Any],
    ) -> None:
        self._id = agent_id
        self._actors = actors
        self._grants = grants
        self._states = states

    async def on_start(self, ctx: AgentContext) -> None:
        """Grant approvals (announced before any action), then pulse the actors.

        Example::

            await coord.on_start(ctx)
        """
        from nest_plugins_reference.policy.decide import approval_key

        for aid, amount in self._grants:
            state = self._states.get(aid)
            if state is not None:
                state.grant(approval_key("pay", amount))
            line = "approval:" + json.dumps({"agent": str(aid), "amount": amount}, sort_keys=True)
            await ctx.send(self._id, line.encode())
        for aid in self._actors:
            await ctx.send(aid, b"go:")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Audit sink — received lines are already recorded in the trace.

        Example::

            await coord.on_message(ctx, AgentId("honest-0"), b"action:{}")
        """
        return


def _provision(
    config: ScenarioConfig, plugins: dict[str, Any]
) -> tuple[dict[AgentId, Any], dict[AgentId, Any]]:
    """Wire identities, signed manifests, per-agent states, and (proxied) plugins.

    Returns ``(states, announced)`` — the per-agent :class:`PolicyState` map (for
    the coordinator to grant approvals) and the as-announced signed manifests (for
    building the actors). Honours the ``enforcement: enforced|permissive`` task
    config: the enforced path wraps each agent's plugins in a
    :class:`PolicyEnforcer` sharing one state per agent; the permissive path hands
    agents the raw plugins.

    Example::

        states, announced = _provision(config, plugins)
    """
    from nest_plugins_reference.policy.decide import PolicyState
    from nest_plugins_reference.policy.enforcer import PolicyEnforcer
    from nest_plugins_reference.policy.manifest import (
        Approval,
        Budget,
        PolicyManifest,
        sign_manifest,
        verify_manifest,
    )

    enforced = str(config.task.config.get("enforcement", "enforced")) == "enforced"
    all_ids = [_COORDINATOR, *_ACTORS]

    # Per-agent identities (cross-registered so each can verify the others).
    identity_cls = plugins.get("identity")
    identities: dict[AgentId, Any] = {}
    if isinstance(identity_cls, type):
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"policy-gov:" + str(aid).encode())
        for aid, ident in identities.items():
            for peer, peer_ident in identities.items():
                if peer != aid and hasattr(ident, "register_peer"):
                    ident.register_peer(peer, peer_ident.public_key)

    def author(aid: AgentId) -> PolicyManifest:
        return PolicyManifest(
            agent_id=aid,
            tools=["sell"],
            data={"default": [str(_COORDINATOR)]},
            budget=Budget(cap=100),
            approvals=[Approval(op="pay", threshold=50)],
        )

    def deny_all(aid: AgentId) -> PolicyManifest:
        return PolicyManifest(agent_id=aid)

    # Sign each actor's manifest with its own key — except the forged agent, whose
    # manifest is signed by a *different* key, so it fails verification.
    signed: dict[AgentId, PolicyManifest] = {}
    for aid in (_HONEST_BASIC, _HONEST_APPROVED, _BYZANTINE):
        ident = identities.get(aid)
        signed[aid] = sign_manifest(ident, author(aid)) if ident is not None else author(aid)
    if isinstance(identity_cls, type):
        attacker = identity_cls(_FORGED, seed=b"attacker-key")
        signed[_FORGED] = sign_manifest(attacker, author(_FORGED))
    else:
        signed[_FORGED] = author(_FORGED)

    # Verify against each agent's real identity; the policy actually enforced is
    # the verified manifest, or deny-all when verification fails (forged).
    enforced_manifest: dict[AgentId, PolicyManifest] = {}
    valid: dict[AgentId, PolicyManifest] = {}
    for aid in _ACTORS:
        ident = identities.get(aid)
        if ident is not None and verify_manifest(ident, signed[aid]):
            enforced_manifest[aid] = signed[aid]
            valid[aid] = signed[aid]
        else:
            enforced_manifest[aid] = deny_all(aid)

    states: dict[AgentId, Any] = {aid: PolicyState() for aid in _ACTORS}

    def wrap(aid: AgentId, raw: Any, data_class: str = "default") -> Any:
        if not enforced:
            return raw
        return PolicyEnforcer(aid, enforced_manifest[aid], raw, states[aid], data_class)

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    # Shared registry instance; per-agent proxies gate each register() call.
    registry_cls = plugins.get("registry")
    shared_registry = registry_cls() if isinstance(registry_cls, type) else None
    if shared_registry is not None:
        plugins["registry"] = shared_registry

    # Shared ledger; each agent gets its own handle (so pay() debits the caller).
    payments_cls = plugins.get("payments")
    balances: dict[AgentId, int] = {aid: 1_000_000 for aid in all_ids}
    payment_records: dict[PaymentRef, Any] = {}
    if isinstance(payments_cls, type):
        plugins["payments"] = payments_cls(
            AgentId("system"), initial_balance=0, balances=balances, payments=payment_records
        )

    privacy_cls = plugins.get("privacy")

    for aid in _ACTORS:
        per = agent_plugins.setdefault(aid, {})
        if isinstance(payments_cls, type):
            handle = payments_cls(
                aid, initial_balance=0, balances=balances, payments=payment_records
            )
            per["payments"] = wrap(aid, handle)
        if shared_registry is not None:
            per["registry"] = wrap(aid, shared_registry)
        if isinstance(privacy_cls, type):
            per["privacy"] = wrap(aid, privacy_cls())

    # policy_auth is the registered auth plugin; it only ever sees verified manifests.
    auth_cls = plugins.get("auth")
    if isinstance(auth_cls, type):
        try:
            plugins["auth"] = auth_cls(dict(valid), clock=0.0)
        except TypeError:
            plugins["auth"] = auth_cls()

    for aid, ident in identities.items():
        agent_plugins.setdefault(aid, {})["identity"] = ident
    plugins.pop("identity", None)

    return states, dict(signed)


def policy_governance_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the coordinator + governed actors for the policy-governance scenario.

    Example::

        agents = policy_governance_factory(config, plugins)
    """
    states, announced = _provision(config, plugins)
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.get("_agent_plugins", {})

    def identity_of(aid: AgentId) -> Any:
        return agent_plugins.get(aid, {}).get("identity")

    agents: dict[AgentId, StateMachineAgent] = {}
    agents[_COORDINATOR] = CoordinatorAgent(
        _COORDINATOR, _ACTORS, grants=[(_HONEST_APPROVED, _APPROVED_AMOUNT)], states=states
    )
    for aid in _ACTORS:
        agents[aid] = GovernedActor(
            aid, _COORDINATOR, announced.get(aid), identity_of(aid), _PLANS[aid]
        )
    return agents
