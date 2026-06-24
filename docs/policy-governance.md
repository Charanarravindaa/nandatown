# Identity-bound policy governance

> Nanda Town can test identity, trust, and payments — but it could not test
> whether an agent *obeys its own declared policy*. This control adds that.

On an open agent network, a fleet discovers and transacts with strangers. That
collapses if a declared identity/capability set isn't tied to actual behaviour.
Across the 12 layers, most security gaps already ship a stub *and* a reference
plugin — but one gap had **no mechanism at all**: declared capabilities are never
enforced against behaviour, and there is no notion of spend caps, data-exposure
limits, or actions requiring authorization. This control fills that gap and lets
the test rig prove an agent stays within an owner-authored, signed policy — or
catch it when it doesn't.

It is **real runtime enforcement** (out-of-policy actions are *blocked*), with an
independent validator layer that *proves* nothing slipped through.

## The four governance dimensions

An agent's owner writes a `PolicyManifest` bounding:

| Dimension | Manifest field | Enforced on |
|---|---|---|
| Tools / capabilities it may use | `tools` | `registry.register`, token scopes |
| Data it may expose, and to whom | `data` (class → audiences) | `privacy.encrypt` |
| How much it may spend | `budget` (cap, currency) | `payments.pay` (cumulative) |
| Actions needing authorization | `approvals` (op, threshold) | over-threshold `payments.pay` |

The manifest is **signed with the agent's own identity key** (Ed25519, via the
`ed25519_rotating` identity plugin). The owner authors the policy, but only a
manifest signed by the agent's key is honoured, and the agent's own code cannot
loosen it at runtime — tampering invalidates the signature.

## Architecture: one decision core, two surfaces, plus audit

```
                       PolicyManifest (signed, identity-bound)
                                   │
                          decide(manifest, op, args, state)   ← the single PDP
                          ┌────────┴─────────────┐
            policy_auth (Auth plugin)      PolicyEnforcer (PEP proxy)
            clamps token scopes            BLOCKS out-of-policy plugin calls
            (unit-tested at the            (raises PolicyViolationError)
             auth layer)                            │
                                          trace (action: / policy_denied:)
                                                    │
                                       policy_governance validators ← prove it held
```

Both surfaces call the one `decide()` core. The **scenario's** runtime block — and
the validator flip below — is driven by the `PolicyEnforcer`; `policy_auth` is the
auth-layer surface of the same decision (its scope-clamp-vs-`jwt` behaviour is
covered by unit tests).

- **PDP — `decide()`** (`nest_plugins_reference/policy/decide.py`): one pure
  function both surfaces call, so they can never disagree on what the policy
  permits.
- **`policy_auth`** (Auth-layer plugin, registered): `issue()` clamps a token's
  scopes to the manifest — the unbounded reference `jwt` mints any scope; this
  mints only manifest-permitted ones. This is the auth-layer surface (unit-tested);
  the scenario demonstration is driven by the `PolicyEnforcer`.
- **`PolicyEnforcer`** (the real block): a per-agent proxy wrapping each layer
  plugin. A governed call that exceeds the manifest raises `PolicyViolationError`
  *before* the underlying effect — money never moves, data is never exposed to
  a disallowed audience, a capability is never registered. In-policy calls
  delegate and update per-agent state (cumulative spend, single-use approvals).
- **Validators** (`VALIDATORS["policy_governance"]`): corroborate from the trace.

## The experiment: one toggle flips everything

The `policy_governance` scenario gives each agent a signed manifest. Honest
agents act in policy; a byzantine agent violates every dimension; a forged-manifest
agent is governed by a deny-all policy. A single config switch is the whole test:

```yaml
task:
  type: policy_governance
  config:
    enforcement: enforced     # or: permissive
```

- `enforced` wraps each agent's plugins in the `PolicyEnforcer`. Byzantine and
  forged attempts are **blocked** — the trace shows no successful violation.
- `permissive` hands agents the raw plugins. The same attempts **succeed**.

All five validators **PASS under `enforced` and FAIL under `permissive`** — same
agents, same scenario, one switch. That is the adversarial-validator contract.

## Run it

```bash
nest run scenarios/policy_governance.yaml -o ./traces/policy_governance.jsonl
python -c "from pathlib import Path; from nest_core.validators import validate_trace; \
[print('PASS' if r.passed else 'FAIL', r.name, '-', r.detail) \
 for r in validate_trace(Path('traces/policy_governance.jsonl'), 'policy_governance')]"
```

Expect all five PASS. Flip `enforcement: permissive` and re-run: all five FAIL.

## Threat model and limitations (what this does and does not defend)

Honesty here is part of the design.

- **No bypass for money, capabilities, or auth.** These move *only* through the
  governed plugins, so wrapping them is airtight: a buggy or compromised agent
  calling those APIs cannot exceed its signed policy.
- **Raw `ctx.send` is the one ungated egress path.** Data is just bytes, so an
  agent could exfiltrate via raw messaging instead of the governed privacy layer.
  In the scenario, data exposure is routed through the privacy layer (governed).
  Closing the raw path for an adversarial agent needs a context-level gate, which
  lives in the simulator core; we kept the submission in-scope (no core edits) and
  document the boundary. The framework has no pluggable per-message egress hook —
  a transport/runtime in a real deployment is where that gate belongs.
- **In-process agents are not sandboxed.** The control governs the plugin *handle*
  an agent is given; an agent reaching around it via Python internals is the same
  un-isolated-runtime limitation. A production runtime isolates the agent.
- **Offline signature verification checks consistency, not ownership.** A validator
  reading the trace confirms the announced key signed the announced manifest; the
  runtime binds key → agent via the identity peer-registry (the trace has no
  trusted key directory).

## Not the same as auth capability-delegation (problem #04)

Problem #04 is about *delegating* capability tokens down a chain with cascading
revocation. This control is about binding an agent's behaviour to its *own*
signed declaration across four dimensions and enforcing it at runtime — a
different axis. `policy_auth` reuses the manifest as the source of truth for token
scopes, but the heart of the control is the `PolicyEnforcer` runtime block and the
validators that prove it held.

## Where this sits in the 12 blocks

This contribution does two things at once:

- **It improves the `auth` block** — `policy_auth` is a new `Auth`-protocol plugin
  (registered via `pyproject.toml` entry point and `_BUILTINS`) that clamps token
  scopes to a signed manifest, where the reference `jwt` clamps nothing.
- **It surfaces a block-shaped gap the stack does not yet have: policy governance.**
  Enforcing an agent's declared behaviour (tools, data, spend, authorization) is
  cross-cutting — it spans payments, registry, and privacy — so it does not fit
  inside any single existing block. We prototype it here as a runtime enforcer + a
  scenario + validators (no core edits), and propose **governance as a candidate
  new block**. Making it a first-class 13th layer (a `policy` entry in the layer
  registry, `LayerConfig`, and the runner) is the natural follow-up.

## Files

- `packages/nest-plugins-reference/nest_plugins_reference/policy/` — `manifest.py`,
  `decide.py`, `enforcer.py`, `scopes.py`.
- `packages/nest-plugins-reference/nest_plugins_reference/auth/policy_auth.py`.
- `packages/nest-core/nest_core/scenarios_builtin/policy_governance.py` +
  `scenarios/policy_governance.yaml`.
- Validators in `packages/nest-core/nest_core/validators.py`
  (`VALIDATORS["policy_governance"]`).
