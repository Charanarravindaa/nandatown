# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for ``policy_auth`` scope clamping.

Invariants over arbitrary requested scope lists:

1. No escalation: every granted scope was requested AND is permitted by the
   manifest (the issued token is a subset of what the manifest allows).
2. Determinism: same subject + scopes + clock -> byte-identical token.

Example::

    pytest packages/nest-plugins-reference/tests/test_policy_auth_properties.py
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.auth.policy_auth import PolicyAuth, scope_to_op
from nest_plugins_reference.policy.decide import PolicyState, decide
from nest_plugins_reference.policy.manifest import Budget, PolicyManifest

_MANIFEST = PolicyManifest(
    agent_id=AgentId("a1"),
    tools=["buy", "sell"],
    data={"pii": ["seller-1"], "public": ["*"]},
    budget=Budget(cap=500),
)

_SCOPES = st.lists(
    st.sampled_from(
        [
            "tool:buy",
            "tool:sell",
            "tool:admin",
            "spend:100",
            "spend:5000",
            "expose:pii:seller-1",
            "expose:pii:seller-9",
            "expose:public:anyone",
            "read",
            "garbage:::",
        ]
    ),
    max_size=8,
)


@settings(max_examples=300)
@given(scopes=_SCOPES)
async def test_no_escalation(scopes: list[str]) -> None:
    auth = PolicyAuth({AgentId("a1"): _MANIFEST}, clock=0.0)
    ctx = await auth.verify(await auth.issue(AgentId("a1"), scopes))
    for scope in ctx.scopes:
        assert scope in scopes  # never invents a scope
        parsed = scope_to_op(scope)
        assert parsed is not None
        op, args = parsed
        assert decide(_MANIFEST, op, args, PolicyState()).allowed  # truly permitted


@settings(max_examples=100)
@given(scopes=_SCOPES)
async def test_issue_is_deterministic(scopes: list[str]) -> None:
    a = PolicyAuth({AgentId("a1"): _MANIFEST}, clock=0.0)
    b = PolicyAuth({AgentId("a1"): _MANIFEST}, clock=0.0)
    assert await a.issue(AgentId("a1"), scopes) == await b.issue(AgentId("a1"), scopes)
