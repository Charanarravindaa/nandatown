# SPDX-License-Identifier: Apache-2.0
"""Tests for the PolicyEnforcer runtime proxy (the real block).

The enforcer now consults the policy layer (a :class:`ManifestPolicy` PDP) before
each governed call; the PDP holds the per-agent state, so spend and approvals are
asserted via ``policy.state_for(agent)``.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentCard, AgentId, Money, PaymentRef, PolicyDecision, Query
from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits
from nest_plugins_reference.policy.decide import PolicyViolationError
from nest_plugins_reference.policy.enforcer import PolicyEnforcer
from nest_plugins_reference.policy.manifest import Approval, Budget, PolicyManifest
from nest_plugins_reference.policy.manifest_policy import ManifestPolicy
from nest_plugins_reference.privacy.noop import NoopPrivacy
from nest_plugins_reference.registry.in_memory import InMemoryRegistry


def _manifest(**kw: object) -> PolicyManifest:
    base: dict[str, object] = {
        "agent_id": AgentId("a1"),
        "tools": ["sell"],
        "data": {"default": ["seller-1"]},
        "budget": Budget(cap=100),
    }
    base.update(kw)
    return PolicyManifest.model_validate(base)


def _policy(manifest: PolicyManifest) -> ManifestPolicy:
    policy = ManifestPolicy()
    policy.add_manifest(manifest)
    return policy


def _payments(agent: str = "a1") -> PrepaidCredits:
    return PrepaidCredits(AgentId(agent), initial_balance=1_000_000)


# --- spend dimension -------------------------------------------------------
async def test_pay_within_budget_delegates() -> None:
    policy = _policy(_manifest())
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    receipt = await enf.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
    assert receipt.amount.amount == 50
    assert policy.state_for(AgentId("a1")).spent["credits"] == 50


async def test_pay_over_budget_blocked() -> None:
    policy = _policy(_manifest())
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    with pytest.raises(PolicyViolationError):
        await enf.pay(AgentId("a2"), Money(amount=500), PaymentRef("p1"))
    # The effect never happened: payer balance untouched, nothing recorded.
    assert enf.balance(AgentId("a1")) == 1_000_000
    assert policy.state_for(AgentId("a1")).spent == {}


async def test_pay_cumulative_cap_blocks_second_call() -> None:
    policy = _policy(_manifest())
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    await enf.pay(AgentId("a2"), Money(amount=60), PaymentRef("p1"))
    with pytest.raises(PolicyViolationError):
        await enf.pay(AgentId("a2"), Money(amount=60), PaymentRef("p2"))  # 60+60 > 100
    assert policy.state_for(AgentId("a1")).spent["credits"] == 60


# --- authorization-required dimension --------------------------------------
async def test_pay_over_threshold_blocked_without_grant() -> None:
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    enf = PolicyEnforcer(AgentId("a1"), _policy(m), _payments())
    with pytest.raises(PolicyViolationError):
        await enf.pay(AgentId("a2"), Money(amount=500), PaymentRef("p1"))


async def test_pay_over_threshold_allowed_with_grant_then_consumed() -> None:
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    policy = _policy(m)
    policy.grant(AgentId("a1"), "pay", 500)
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    await enf.pay(AgentId("a2"), Money(amount=500), PaymentRef("p1"))  # uses the grant
    # Grant is single-use: a second identical large pay is blocked.
    with pytest.raises(PolicyViolationError):
        await enf.pay(AgentId("a2"), Money(amount=500), PaymentRef("p2"))


# --- tools / capabilities dimension ----------------------------------------
async def test_register_within_allowlist_delegates() -> None:
    reg = InMemoryRegistry()
    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest(tools=["sell"])), reg)
    await enf.register(AgentCard(agent_id=AgentId("a1"), name="A", capabilities=["sell"]))
    results = await reg.lookup(Query())
    assert any(c.agent_id == AgentId("a1") for c in results)


async def test_register_overclaim_blocked() -> None:
    reg = InMemoryRegistry()
    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest(tools=["sell"])), reg)
    with pytest.raises(PolicyViolationError):
        await enf.register(
            AgentCard(agent_id=AgentId("a1"), name="A", capabilities=["sell", "admin"])
        )


# --- data exposure dimension -----------------------------------------------
async def test_encrypt_allowed_audience_delegates() -> None:
    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest()), NoopPrivacy())
    out = await enf.encrypt(b"secret", [AgentId("seller-1")])
    assert out == b"secret"  # noop returns data; the point is it was NOT blocked


async def test_encrypt_disallowed_audience_blocked() -> None:
    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest()), NoopPrivacy())
    with pytest.raises(PolicyViolationError):
        await enf.encrypt(b"secret", [AgentId("seller-9")])


# --- delegation / isolation ------------------------------------------------
async def test_delegates_non_governed_methods() -> None:
    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest()), _payments())
    assert enf.balance(AgentId("a1")) == 1_000_000  # via __getattr__


class _RaisingPayments:
    """A payments stub whose pay() raises after the gate has passed."""

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> object:
        raise ValueError("insufficient funds")


async def test_wrapped_pay_error_leaves_state_clean() -> None:
    # If the wrapped plugin raises AFTER the gate allows, no spend is recorded
    # and a pre-granted approval is not consumed (record/discard run only on success).
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    policy = _policy(m)
    policy.grant(AgentId("a1"), "pay", 500)
    enf = PolicyEnforcer(AgentId("a1"), policy, _RaisingPayments())
    with pytest.raises(ValueError, match="insufficient"):
        await enf.pay(AgentId("a2"), Money(amount=500), PaymentRef("p1"))
    assert policy.state_for(AgentId("a1")).spent == {}
    assert "pay:500" in policy.state_for(AgentId("a1")).approvals


async def test_currency_mismatch_blocked() -> None:
    policy = _policy(_manifest(budget=Budget(cap=100)))
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    with pytest.raises(PolicyViolationError):
        await enf.pay(AgentId("a2"), Money(amount=10, currency="usd"), PaymentRef("p1"))
    assert policy.state_for(AgentId("a1")).spent == {}


async def test_under_threshold_pay_needs_no_grant() -> None:
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    policy = _policy(m)
    enf = PolicyEnforcer(AgentId("a1"), policy, _payments())
    await enf.pay(AgentId("a2"), Money(amount=150), PaymentRef("p1"))  # under threshold, no grant
    assert policy.state_for(AgentId("a1")).spent["credits"] == 150


async def test_delegates_async_non_governed_methods() -> None:
    from nest_core.types import ServiceRef

    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest()), _payments())
    quote = await enf.quote(ServiceRef("svc"))  # via __getattr__, awaited
    assert quote.price.amount == 10


def test_deepcopy_does_not_recurse() -> None:
    import copy

    enf = PolicyEnforcer(AgentId("a1"), _policy(_manifest()), _payments())
    clone = copy.deepcopy(enf)  # must not RecursionError
    assert isinstance(clone, PolicyEnforcer)


async def test_per_identity_isolation() -> None:
    # Two agents share one policy (and one ledger) but their per-agent state is
    # isolated, so one's spend never affects the other's cap.
    shared_ledger = _payments("a1")
    policy = ManifestPolicy()
    policy.add_manifest(_manifest(agent_id=AgentId("a1"), budget=Budget(cap=100)))
    policy.add_manifest(_manifest(agent_id=AgentId("a2"), budget=Budget(cap=100)))
    enf1 = PolicyEnforcer(AgentId("a1"), policy, shared_ledger)
    enf2 = PolicyEnforcer(AgentId("a2"), policy, shared_ledger)
    await enf1.pay(AgentId("x"), Money(amount=90), PaymentRef("a1-p1"))
    # a2 still has its full cap; a1's spend did not bleed across.
    await enf2.pay(AgentId("x"), Money(amount=90), PaymentRef("a2-p1"))
    assert policy.state_for(AgentId("a1")).spent["credits"] == 90
    assert policy.state_for(AgentId("a2")).spent["credits"] == 90


class _DenyingPolicy:
    """A stub Policy that denies everything — proves the enforcer is load-bearing."""

    async def authorize(self, agent: AgentId, op: str, args: dict[str, object]) -> PolicyDecision:
        return PolicyDecision(allowed=False, reason="stub-deny")

    def record_success(self, agent: AgentId, op: str, args: dict[str, object]) -> None: ...


async def test_enforcer_decision_flows_through_the_policy_layer() -> None:
    # The block is the policy layer's call, not the enforcer's own logic: a denying
    # policy makes an otherwise-fine pay raise, carrying the policy's reason.
    enf = PolicyEnforcer(AgentId("a1"), _DenyingPolicy(), _payments())
    with pytest.raises(PolicyViolationError, match="stub-deny"):
        await enf.pay(AgentId("a2"), Money(amount=1), PaymentRef("p1"))
