# SPDX-License-Identifier: Apache-2.0
"""Policy-bound auth: HMAC tokens whose scopes are clamped to a signed manifest.

This is one of two enforcement surfaces over the shared decision core
(:func:`nest_plugins_reference.policy.decide.decide`); the other is the runtime
:class:`~nest_plugins_reference.policy.enforcer.PolicyEnforcer` proxy. Unlike
the reference ``jwt`` auth (which mints whatever scopes are requested),
:class:`PolicyAuth` only grants scopes the subject's manifest permits — a
requested scope outside the manifest is dropped from the issued token, and a
subject with no manifest gets a deny-all (empty-scope) token. So at the auth
layer this denies a scope that ``jwt`` would hand out (see the unit test
``test_flip_vs_jwt_at_auth_layer``). In the ``policy_governance`` scenario the
runtime block is driven by the :class:`PolicyEnforcer` toggle, not by this
plugin; ``policy_auth`` is the auth-layer surface of the same decision core.

Manifest *signature* verification is the scenario factory's job — it binds each
manifest to the agent's identity at wrap time and only hands verified manifests
to this plugin (a forged/unsigned manifest is simply withheld, yielding deny-all).
This plugin enforces the manifest's *content* via the shared decision core.

Scope grammar (parsed against the manifest):

- ``tool:<name>``                    -> decide("tool", {"name": ...})
- ``spend:<int>``                    -> decide("pay", {"amount": ...})
- ``expose:<class>:<aud1,aud2,...>`` -> decide("expose", {"data_class", "audience"})

Example::

    auth = PolicyAuth({AgentId("a1"): manifest}, clock=0.0)
    token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:admin"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["tool:buy"]  # "tool:admin" dropped (not in manifest)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

from nest_core.types import AgentId, AuthContext, Token

from nest_plugins_reference.policy.decide import PolicyState, decide
from nest_plugins_reference.policy.manifest import PolicyManifest
from nest_plugins_reference.policy.scopes import scope_to_op as scope_to_op  # re-export


class PolicyAuth:
    """Auth plugin that clamps issued token scopes to the subject's manifest.

    Implements the structural :class:`nest_core.layers.auth.Auth` protocol
    (``issue``/``verify``/``revoke``). The token shape mirrors the reference
    ``jwt`` plugin (``payload|hmac``) so existing verifiers/traces are familiar;
    the difference is *which* scopes end up in the token.

    Example::

        auth = PolicyAuth({AgentId("a1"): manifest})
        token = await auth.issue(AgentId("a1"), ["tool:buy"])
    """

    def __init__(
        self,
        manifests: dict[AgentId, PolicyManifest] | None = None,
        secret: bytes = b"nest-policy-secret",
        clock: float | None = None,
    ) -> None:
        # Pass ``clock`` on any deterministic (trace) path; the ``time.time()``
        # fallback (mirroring ``jwt``) is non-deterministic and for ad-hoc use only.
        self._manifests = manifests or {}
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def _granted_scopes(self, subject: AgentId, scopes: list[str]) -> list[str]:
        """Return the subset of *scopes* the subject's manifest permits.

        Order-preserving and de-duplicated (deterministic). A subject without a
        manifest yields an empty list (deny-all). ``spend`` scopes are checked
        per-action against the cap with a fresh state; cumulative spend and
        approval gating are enforced at runtime by the enforcer proxy, not by
        the durable token.
        """
        manifest = self._manifests.get(subject)
        if manifest is None:
            return []
        granted: list[str] = []
        for scope in scopes:
            if scope in granted:
                continue
            parsed = scope_to_op(scope)
            if parsed is None:
                continue
            op, args = parsed
            if decide(manifest, op, args, PolicyState()).allowed:
                granted.append(scope)
        return granted

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a token carrying only the manifest-permitted subset of *scopes*.

        Example::

            token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:admin"])
        """
        now = self._now()
        granted = self._granted_scopes(subject, scopes)
        payload = json.dumps(
            {"sub": str(subject), "scopes": granted, "iat": now, "exp": now + 3600},
            sort_keys=True,
        )
        sig = self._sign(payload)
        return Token(f"{payload}|{sig}")

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token and return its auth context.

        Example::

            ctx = await auth.verify(token)
            assert ctx.subject == AgentId("a1")
        """
        raw = str(token)
        if raw in self._revoked:
            msg = "Token has been revoked"
            raise ValueError(msg)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise ValueError(msg)
        payload_str, sig = parts
        expected = self._sign(payload_str)
        if not hmac.compare_digest(sig, expected):
            msg = "Invalid token signature"
            raise ValueError(msg)
        data = json.loads(payload_str)
        if data["exp"] < self._now():
            msg = "Token has expired"
            raise ValueError(msg)
        return AuthContext(
            subject=AgentId(data["sub"]),
            scopes=data["scopes"],
            issued_at=data["iat"],
            expires_at=data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a previously issued token.

        Example::

            await auth.revoke(token)
        """
        self._revoked.add(str(token))
