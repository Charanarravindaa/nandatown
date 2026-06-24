# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the policy_governance scenario.

Proves the scenario is deterministic and that the single ``enforcement`` toggle
flips behaviour: under ``enforced`` the byzantine and forged agents are blocked
(no successful ``action:`` lines), while under ``permissive`` the same attempts
succeed. The validator-level flip lives in M5's test_validators.

Example::

    pytest packages/nest-core/tests/test_policy_governance.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "policy_governance.yaml"


def _config(trace: Path, enforcement: str) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_YAML)
    config.task.config["enforcement"] = enforcement
    config.output.trace = str(trace)
    return config


def _emitted(trace: Path, agent: str, prefix: str) -> list[str]:
    """Return the msg bodies an *agent* emitted (send events) starting with *prefix*."""
    out: list[str] = []
    for line in trace.read_text().splitlines():
        event = json.loads(line)
        if event.get("kind") == "send" and event.get("agent") == agent:
            msg = str(event.get("msg", ""))
            if msg.startswith(prefix):
                out.append(msg)
    return out


def _manifest_announcements(trace: Path) -> dict[str, dict[str, Any]]:
    """Map agent -> its announced manifest body ({agent, manifest, pubkey})."""
    out: dict[str, dict[str, Any]] = {}
    for line in trace.read_text().splitlines():
        event = json.loads(line)
        if event.get("kind") == "send" and str(event.get("msg", "")).startswith("manifest:"):
            body = json.loads(str(event["msg"])[len("manifest:") :])
            out[str(body["agent"])] = body
    return out


async def test_enforced_blocks_byzantine_and_forged(tmp_path: Path) -> None:
    trace = tmp_path / "enforced.jsonl"
    result = await ScenarioRunner(_config(trace, "enforced")).run()

    # Honest agents act successfully.
    assert _emitted(result, "honest-0", "action:")  # register/pay/expose all succeed
    assert _emitted(result, "honest-1", "action:")  # the approved over-threshold pay

    # Byzantine + forged are blocked: no successful actions, only denials.
    assert _emitted(result, "byzantine-0", "action:") == []
    assert len(_emitted(result, "byzantine-0", "policy_denied:")) == 4
    assert _emitted(result, "forged-0", "action:") == []
    assert _emitted(result, "forged-0", "policy_denied:")


async def test_enforced_no_successful_violation(tmp_path: Path) -> None:
    # The strong, single guarantee: under enforced, neither byzantine nor forged
    # produced ANY successful governed action.
    trace = tmp_path / "enforced.jsonl"
    result = await ScenarioRunner(_config(trace, "enforced")).run()
    assert _emitted(result, "byzantine-0", "action:") == []
    assert _emitted(result, "forged-0", "action:") == []


async def test_approved_pay_present_under_enforced(tmp_path: Path) -> None:
    trace = tmp_path / "enforced.jsonl"
    result = await ScenarioRunner(_config(trace, "enforced")).run()
    # honest-1's over-threshold pay (80 > 50) succeeds because the coordinator
    # granted the matching approval, and the approval line is announced.
    pays = _emitted(result, "honest-1", "action:")
    assert any('"amount": 80' in p and '"op": "pay"' in p for p in pays)
    assert _emitted(result, "coordinator-0", "approval:")


async def test_manifest_signatures_verifiable_offline(tmp_path: Path) -> None:
    # The linchpin: M5 must be able to verify each announced manifest's signature
    # offline against the announced pubkey, and detect the forged one.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from nest_plugins_reference.policy.manifest import PolicyManifest

    trace = tmp_path / "enforced.jsonl"
    result = await ScenarioRunner(_config(trace, "enforced")).run()
    announcements = _manifest_announcements(result)
    assert set(announcements) == {"honest-0", "honest-1", "byzantine-0", "forged-0"}

    def verifies(agent: str) -> bool:
        body = announcements[agent]
        manifest = PolicyManifest.model_validate(body["manifest"])
        assert manifest.signature is not None
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(body["pubkey"])))
        try:
            pub.verify(manifest.signature.value, manifest.signing_bytes())
        except InvalidSignature:
            return False
        return True

    assert verifies("honest-0")
    assert verifies("honest-1")
    assert verifies("byzantine-0")
    assert not verifies("forged-0")  # signed by an attacker key -> detectable


async def test_permissive_allows_violations(tmp_path: Path) -> None:
    trace = tmp_path / "permissive.jsonl"
    result = await ScenarioRunner(_config(trace, "permissive")).run()

    # Without the enforcer, the same byzantine attempts succeed.
    assert len(_emitted(result, "byzantine-0", "action:")) == 4
    assert _emitted(result, "byzantine-0", "policy_denied:") == []
    assert _emitted(result, "forged-0", "action:")  # forged agent's register succeeds


async def test_deterministic_both_modes(tmp_path: Path) -> None:
    for enforcement in ("enforced", "permissive"):
        traces: list[str] = []
        for i in range(2):
            trace = tmp_path / f"{enforcement}-{i}.jsonl"
            await ScenarioRunner(_config(trace, enforcement)).run()
            traces.append(trace.read_text())
        assert traces[0] == traces[1], f"{enforcement} not deterministic"
        assert len(traces[0]) > 0
