# SPDX-License-Identifier: Apache-2.0
"""Identity-bound policy governance: signed manifests, one decision core, enforcement.

This package gives every agent an owner-authored, cryptographically-signed
:class:`~nest_plugins_reference.policy.manifest.PolicyManifest` that bounds its
behaviour across four governance dimensions — which tools/actions it may call,
what data it may expose (and to whom), how much it may spend, and which actions
require prior authorization.

A single decision core (:func:`~nest_plugins_reference.policy.decide.decide`) is
shared by both enforcement surfaces so they can never drift: the ``policy_auth``
Auth plugin clamps token scopes at issuance, and the
:class:`~nest_plugins_reference.policy.enforcer.PolicyEnforcer` proxy blocks
out-of-policy calls at runtime.

Example::

    from nest_plugins_reference.policy import PolicyManifest, Budget, decide
"""

from __future__ import annotations

from nest_plugins_reference.policy.decide import (
    Decision,
    PolicyState,
    PolicyViolationError,
    decide,
)
from nest_plugins_reference.policy.manifest import (
    Approval,
    Budget,
    ManifestSigner,
    PolicyManifest,
    sign_manifest,
    verify_manifest,
)

__all__ = [
    "Approval",
    "Budget",
    "Decision",
    "ManifestSigner",
    "PolicyManifest",
    "PolicyState",
    "PolicyViolationError",
    "decide",
    "sign_manifest",
    "verify_manifest",
]
