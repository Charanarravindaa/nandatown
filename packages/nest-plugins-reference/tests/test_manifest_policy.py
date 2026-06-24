# SPDX-License-Identifier: Apache-2.0
"""Tests for the ManifestPolicy PDP — the load-bearing policy-layer plugin.

Covers the Policy contract directly (authorize allow/deny per dimension,
record_success spend tracking, single-use grants, deny-all for unknown agents),
plus protocol conformance and registry resolution.
"""

from __future__ import annotations

from nest_core.layers.policy import Policy
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId
from nest_plugins_reference.policy.manifest import Approval, Budget, PolicyManifest
from nest_plugins_reference.policy.manifest_policy import ManifestPolicy

_A1 = AgentId("a1")


def _manifest(**kw: object) -> PolicyManifest:
    base: dict[str, object] = {
        "agent_id": _A1,
        "tools": ["sell"],
        "data": {"default": ["seller-1"]},
        "budget": Budget(cap=100),
    }
    base.update(kw)
    return PolicyManifest.model_validate(base)


def _policy(manifest: PolicyManifest | None = None) -> ManifestPolicy:
    policy = ManifestPolicy()
    policy.add_manifest(manifest if manifest is not None else _manifest())
    return policy


# --- authorize: allow per dimension ----------------------------------------
async def test_authorize_allows_in_policy_pay() -> None:
    assert (await _policy().authorize(_A1, "pay", {"amount": 50})).allowed


async def test_authorize_allows_in_policy_register() -> None:
    assert (await _policy().authorize(_A1, "register", {"capabilities": ["sell"]})).allowed


async def test_authorize_allows_in_policy_expose() -> None:
    decision = await _policy().authorize(
        _A1, "expose", {"data_class": "default", "audience": ["seller-1"]}
    )
    assert decision.allowed


# --- authorize: deny per dimension -----------------------------------------
async def test_authorize_denies_overspend() -> None:
    decision = await _policy().authorize(_A1, "pay", {"amount": 500})
    assert not decision.allowed
    assert decision.reason


async def test_authorize_denies_forbidden_capability() -> None:
    decision = await _policy().authorize(_A1, "register", {"capabilities": ["admin"]})
    assert not decision.allowed


async def test_authorize_denies_disallowed_audience() -> None:
    decision = await _policy().authorize(
        _A1, "expose", {"data_class": "default", "audience": ["evil-corp"]}
    )
    assert not decision.allowed


async def test_authorize_denies_over_threshold_without_grant() -> None:
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    decision = await _policy(m).authorize(_A1, "pay", {"amount": 500})
    assert not decision.allowed


# --- record_success / grant ------------------------------------------------
async def test_record_success_records_spend() -> None:
    policy = _policy()
    policy.record_success(_A1, "pay", {"amount": 40})
    assert policy.state_for(_A1).spent["credits"] == 40
    # The recorded spend is cumulative: a later pay that would exceed the cap is denied.
    assert not (await policy.authorize(_A1, "pay", {"amount": 70})).allowed


async def test_record_success_respects_currency() -> None:
    policy = _policy()
    policy.record_success(_A1, "pay", {"amount": 10, "currency": "usd"})
    assert policy.state_for(_A1).spent == {"usd": 10}


async def test_record_success_rejects_non_int_amount() -> None:
    # Mirrors decide(): a float/bool amount records nothing (no truncation bypass),
    # so the cumulative-cap invariant lives in the policy core, not the caller.
    policy = _policy()
    policy.record_success(_A1, "pay", {"amount": 100.9})  # would truncate to 100
    policy.record_success(_A1, "pay", {"amount": True})
    assert policy.state_for(_A1).spent == {}


async def test_grant_enables_over_threshold_pay() -> None:
    m = _manifest(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    policy = _policy(m)
    assert not (await policy.authorize(_A1, "pay", {"amount": 500})).allowed
    policy.grant(_A1, "pay", 500)
    assert (await policy.authorize(_A1, "pay", {"amount": 500})).allowed
    # record_success consumes the single-use grant.
    policy.record_success(_A1, "pay", {"amount": 500})
    assert "pay:500" not in policy.state_for(_A1).approvals


# --- deny-all for unknown agents -------------------------------------------
async def test_unknown_agent_is_denied_all() -> None:
    policy = ManifestPolicy()
    unknown = AgentId("nobody")
    assert not (await policy.authorize(unknown, "pay", {"amount": 1})).allowed
    assert not (await policy.authorize(unknown, "register", {"capabilities": ["sell"]})).allowed
    assert not (
        await policy.authorize(unknown, "expose", {"data_class": "default", "audience": ["x"]})
    ).allowed


# --- state isolation -------------------------------------------------------
def test_state_for_is_stable() -> None:
    policy = ManifestPolicy()
    assert policy.state_for(_A1) is policy.state_for(_A1)


# --- protocol conformance + resolution -------------------------------------
def test_satisfies_policy_protocol() -> None:
    assert isinstance(ManifestPolicy(), Policy)


def test_resolvable_via_registry() -> None:
    cls = PluginRegistry().resolve("policy", "manifest_policy")
    assert cls is ManifestPolicy
