# Policy layer

**What it does.** Govern what an agent may do — which tools it may
call, what data it may expose, how much it may spend, and which actions
need prior authorization. The policy layer is the decision authority:
given an agent, a governed operation, and its arguments, it returns
whether the action is permitted by that agent's policy.

## Interface

```python
class Policy(Protocol):
    async def authorize(self, agent: AgentId, op: str, args: dict[str, Any]) -> PolicyDecision: ...
    def record_success(self, agent: AgentId, op: str, args: dict[str, Any]) -> None: ...
```

`authorize` decides; `record_success` lets a stateful policy track
cumulative effects (e.g. spend) and consume one-shot grants. A
stateless policy treats `record_success` as a no-op.

Full definition: [`nest_core/layers/policy.py`](../../packages/nest-core/nest_core/layers/policy.py).

## Default plugin

`allow_all` — **permissive passthrough.** Authorizes every action and
records nothing. It is the default, so every scenario that does not
select a policy behaves exactly as if no policy layer existed.

Source: [`nest_plugins_reference/policy/allow_all.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/allow_all.py).

## Reference plugin

`manifest_policy` — the real Policy Decision Point. It holds each
agent's verified, identity-signed `PolicyManifest` plus per-agent state,
and answers `authorize` by running the shared `decide()` core for that
agent's manifest (deny-all for an agent with no registered manifest).
An enforcement proxy ([`PolicyEnforcer`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/enforcer.py))
consults it before each governed call and reports `record_success`
afterwards, so out-of-policy actions are blocked at runtime. See
[`policy-governance.md`](../policy-governance.md) for the full story.

Source: [`nest_plugins_reference/policy/manifest_policy.py`](../../packages/nest-plugins-reference/nest_plugins_reference/policy/manifest_policy.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md). Register under
entry point group `nest.plugins.policy`.

Good fits to test here: OPA/Rego or Cedar evaluators, capability-based
allow-lists, rate or budget limiters, human-in-the-loop approval gates,
data-classification egress controls.
