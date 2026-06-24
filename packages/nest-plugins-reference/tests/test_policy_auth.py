# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``policy_auth`` Auth plugin (scope clamping to the manifest)."""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.auth.policy_auth import PolicyAuth
from nest_plugins_reference.policy.manifest import Approval, Budget, PolicyManifest
from nest_plugins_reference.policy.scopes import scope_to_op


def _auth() -> PolicyAuth:
    manifest = PolicyManifest(
        agent_id=AgentId("a1"),
        tools=["buy"],
        data={"pii": ["seller-1"]},
        budget=Budget(cap=500),
        approvals=[Approval(op="pay", threshold=200)],
    )
    return PolicyAuth({AgentId("a1"): manifest}, clock=0.0)


async def test_issue_clamps_disallowed_tool_scope() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:admin"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["tool:buy"]


async def test_issue_clamps_overspend_scope() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["spend:100", "spend:1000"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["spend:100"]


async def test_issue_clamps_disallowed_audience() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["expose:pii:seller-1", "expose:pii:seller-2"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["expose:pii:seller-1"]


async def test_ungoverned_scope_dropped() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["read", "write", "tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["tool:buy"]


async def test_unknown_subject_is_deny_all() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("ghost"), ["tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.scopes == []


async def test_verify_roundtrip_and_revoke() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.subject == AgentId("a1")
    await auth.revoke(token)
    with pytest.raises(ValueError, match="revoked"):
        await auth.verify(token)


async def test_tampered_token_rejected() -> None:
    auth = _auth()
    token = await auth.issue(AgentId("a1"), ["tool:buy"])
    tampered = type(token)(str(token).replace("tool:buy", "tool:admin"))
    with pytest.raises(ValueError, match="signature"):
        await auth.verify(tampered)


async def test_flip_vs_jwt_at_auth_layer() -> None:
    # The charter contract at the auth layer: jwt keeps the disallowed scope,
    # policy_auth drops it. Same requested scopes, different surface.
    requested = ["tool:buy", "tool:admin"]
    jwt = JwtAuth(clock=0.0)
    jwt_ctx = await jwt.verify(await jwt.issue(AgentId("a1"), requested))
    assert "tool:admin" in jwt_ctx.scopes

    policy = _auth()
    policy_ctx = await policy.verify(await policy.issue(AgentId("a1"), requested))
    assert "tool:admin" not in policy_ctx.scopes


async def test_expired_token_rejected() -> None:
    issuer = _auth()  # clock=0.0, so exp = 3600
    token = await issuer.issue(AgentId("a1"), ["tool:buy"])
    # A verifier at a later clock (same default secret) sees the token expired.
    later = PolicyAuth({}, clock=10_000.0)
    with pytest.raises(ValueError, match="expired"):
        await later.verify(token)


async def test_approval_gated_spend_dropped_at_issuance() -> None:
    # spend over the approval threshold cannot be expressed as a durable token
    # scope (approvals are granted at runtime via the enforcer), so it is dropped.
    auth = _auth()  # Budget(cap=500), Approval(op="pay", threshold=200)
    ctx = await auth.verify(await auth.issue(AgentId("a1"), ["spend:300"]))
    assert ctx.scopes == []


async def test_granted_scopes_dedup_and_order_preserved() -> None:
    auth = _auth()
    ctx = await auth.verify(await auth.issue(AgentId("a1"), ["spend:100", "tool:buy", "spend:100"]))
    assert ctx.scopes == ["spend:100", "tool:buy"]


def test_satisfies_auth_protocol() -> None:
    assert isinstance(_auth(), Auth)


def test_resolvable_via_plugin_registry() -> None:
    cls = PluginRegistry().resolve("auth", "policy_auth")
    assert cls is PolicyAuth


# scope_to_op grammar oracle (the grammar the trace validators reuse).
def test_scope_grammar_oracle() -> None:
    assert scope_to_op("tool:buy") == ("tool", {"name": "buy"})
    assert scope_to_op("spend:100") == ("pay", {"amount": 100})
    assert scope_to_op("expose:pii:a,b") == (
        "expose",
        {"data_class": "pii", "audience": ["a", "b"]},
    )
    # malformed / ungoverned -> None (not grantable)
    assert scope_to_op("read") is None
    assert scope_to_op("tool:a:b") is None
    assert scope_to_op("tool:") == ("tool", {"name": ""})
    assert scope_to_op("spend:abc") is None
    assert scope_to_op("spend:100.9") is None
    assert scope_to_op("expose:pii:") is None  # empty audience authorises nothing


async def test_token_unparseable_rejected() -> None:
    # A garbage token must fail verification, never silently grant scopes.
    auth = _auth()
    with pytest.raises(ValueError, match="Invalid token format"):
        await auth.verify(Token("not-a-valid-token"))
