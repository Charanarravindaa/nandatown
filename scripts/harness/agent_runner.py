# SPDX-License-Identifier: Apache-2.0
"""Spawn an agent for one cell × one replicate and collect its submission.

Two transport implementations live here so the harness is runnable from a
plain shell (i.e. outside Claude Code):

* ``ClaudeCLIAgentRunner`` shells out to ``claude -p ... --output-format
  stream-json``. This is the **reference** implementation — simplest, no extra
  Python deps, easiest to reproduce. It assumes the user has the ``claude``
  CLI installed and authenticated.
* ``FixtureAgentRunner`` is the dry-run transport used by tests. It reads a
  JSON fixture from ``scripts/harness/dry_run/fixtures`` and replays it as if
  it were a real agent submission. No network, no cost.

Both transports produce a :class:`AgentSubmission` describing what the agent
produced. The runner is intentionally I/O-light: it does **not** call GitHub
or run CI itself. ``run_condition.py`` is in charge of post-processing
(parsing the PR URL, looking up CI, etc.).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast


@dataclass(frozen=True)
class AgentSpawnSpec:
    """Inputs needed to spawn one agent."""

    cell_id: str
    run_idx: int
    model: str
    brief_path: Path
    brief_text: str
    prompt_hash: str
    seed: int
    workdir: Path
    timeout_seconds: int = 1800
    extra_env: dict[str, str] = field(default_factory=dict[str, str])


@dataclass
class AgentSubmission:
    """Everything we managed to extract about one agent's submission attempt.

    Fields are intentionally permissive — missing fields are recorded as
    ``None`` rather than failing the row, because the goal is to capture
    partial data even when the agent crashed mid-run.
    """

    spawned: bool
    exit_code: int | None
    pr_url: str | None = None
    branch: str | None = None
    head_sha: str | None = None
    layer_picked: str | None = None
    final_message: str | None = None
    transcript_path: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict[str, Any])
    duration_seconds: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class AgentRunner(Protocol):
    """Protocol for any agent transport (CLI, SDK, fixture, ...)."""

    name: str

    def run(self, spec: AgentSpawnSpec) -> AgentSubmission:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# Fixture transport (used by the default test suite — no real agent involved).
# ---------------------------------------------------------------------------


@dataclass
class FixtureAgentRunner:
    """Replay a recorded agent run from a JSON fixture.

    Fixtures live in ``scripts/harness/dry_run/fixtures``. The selection
    algorithm is deterministic: ``fixture_for(cell_id, run_idx)`` picks one of
    the available fixtures by stable hash, so a given (cell, run) pair always
    replays the same fixture across machines.
    """

    fixtures_dir: Path
    name: str = "fixture"

    def run(self, spec: AgentSpawnSpec) -> AgentSubmission:
        fixture = self._select_fixture(spec.cell_id, spec.run_idx)
        with fixture.open("r", encoding="utf-8") as fh:
            data_obj: object = json.load(fh)
        if not isinstance(data_obj, dict):
            raise ValueError(f"{fixture}: fixture must contain a JSON object")
        data = cast("dict[str, Any]", data_obj)

        transcript_path = spec.workdir / f"transcript-{spec.cell_id}-{spec.run_idx}.json"
        spec.workdir.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("w", encoding="utf-8") as fh:
            json.dump(
                {"fixture": fixture.name, "spec": _spec_to_jsonable(spec), "replay": data},
                fh,
                indent=2,
            )

        return AgentSubmission(
            spawned=True,
            exit_code=int(data.get("exit_code", 0)),
            pr_url=data.get("pr_url"),
            branch=data.get("branch"),
            head_sha=data.get("head_sha"),
            layer_picked=data.get("layer_picked"),
            final_message=data.get("final_message"),
            transcript_path=str(transcript_path),
            raw_metadata={
                "fixture_name": fixture.name,
                "claimed_ci_green": bool(data.get("claimed_ci_green", False)),
                "actual_ci_green_first_push": data.get("actual_ci_green_first_push"),
                "iterations_to_green": data.get("iterations_to_green"),
                "lines_added": data.get("lines_added"),
                "lines_removed": data.get("lines_removed"),
                "description": data.get("description"),
            },
            duration_seconds=float(data.get("duration_seconds", 0.0)),
        )

    def _select_fixture(self, cell_id: str, run_idx: int) -> Path:
        fixtures = sorted(self.fixtures_dir.glob("*.json"))
        if not fixtures:
            raise FileNotFoundError(
                f"No fixture JSON files found in {self.fixtures_dir} — cannot dry-run"
            )
        key = f"{cell_id}:{run_idx}".encode()
        idx = int(hashlib.sha256(key).hexdigest(), 16) % len(fixtures)
        return fixtures[idx]


# ---------------------------------------------------------------------------
# Claude CLI transport (the reference live implementation).
# ---------------------------------------------------------------------------


@dataclass
class ClaudeCLIAgentRunner:
    """Shell out to the ``claude`` CLI in headless mode.

    This is the simpler / more reproducible path documented in the README:
    no Python SDK, no tool-loop bookkeeping — the CLI handles all of that.
    We only have to:

    1. Write the brief into the worktree as ``BRIEF.md``.
    2. Invoke ``claude -p <prompt> --output-format stream-json`` with the
       worktree as cwd.
    3. Stream stdout to a transcript file.
    4. Best-effort scrape the last assistant message for a PR URL / branch /
       layer name so we have *something* to write into the JSONL even if
       the rest of the pipeline fails to find the PR on GitHub.

    The actual PR-and-CI lookup happens in ``run_condition.py`` after the
    agent exits.
    """

    binary: str = "claude"
    name: str = "claude-cli"

    def run(self, spec: AgentSpawnSpec) -> AgentSubmission:
        if shutil.which(self.binary) is None:
            return AgentSubmission(
                spawned=False,
                exit_code=None,
                error=f"{self.binary!r} not found on PATH; install Claude Code or use --dry-run",
            )

        spec.workdir.mkdir(parents=True, exist_ok=True)
        brief_dest = spec.workdir / "BRIEF.md"
        brief_dest.write_text(spec.brief_text, encoding="utf-8")

        transcript_path = spec.workdir / f"transcript-{spec.cell_id}-{spec.run_idx}.jsonl"
        env = {**os.environ, **spec.extra_env, "NEST_HARNESS_SEED": str(spec.seed)}

        prompt = (
            f"Read BRIEF.md in the current directory. Follow it exactly. "
            f"Model: {spec.model}. Harness seed: {spec.seed}."
        )
        cmd: list[str] = [
            self.binary,
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--model",
            spec.model,
        ]

        started = time.monotonic()
        final_message: str | None = None
        exit_code: int | None = None
        try:
            with transcript_path.open("w", encoding="utf-8") as transcript:
                proc = subprocess.run(  # noqa: S603 — input is harness-controlled
                    cmd,
                    cwd=spec.workdir,
                    env=env,
                    stdout=transcript,
                    stderr=subprocess.PIPE,
                    timeout=spec.timeout_seconds,
                    check=False,
                )
            exit_code = proc.returncode
            final_message = _scrape_final_message(transcript_path)
        except subprocess.TimeoutExpired:
            return AgentSubmission(
                spawned=True,
                exit_code=None,
                transcript_path=str(transcript_path),
                duration_seconds=time.monotonic() - started,
                error=f"timeout after {spec.timeout_seconds}s",
            )
        except OSError as exc:
            return AgentSubmission(
                spawned=False,
                exit_code=None,
                error=f"failed to spawn {self.binary!r}: {exc}",
            )

        duration = time.monotonic() - started
        pr_url, branch, layer_picked = _scrape_submission_fields(final_message or "")

        return AgentSubmission(
            spawned=True,
            exit_code=exit_code,
            pr_url=pr_url,
            branch=branch,
            head_sha=None,  # filled in by run_condition.py via gh
            layer_picked=layer_picked,
            final_message=final_message,
            transcript_path=str(transcript_path),
            duration_seconds=duration,
        )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _spec_to_jsonable(spec: AgentSpawnSpec) -> dict[str, Any]:
    return {
        "cell_id": spec.cell_id,
        "run_idx": spec.run_idx,
        "model": spec.model,
        "brief_path": str(spec.brief_path),
        "prompt_hash": spec.prompt_hash,
        "seed": spec.seed,
        "workdir": str(spec.workdir),
        "timeout_seconds": spec.timeout_seconds,
    }


def _scrape_final_message(transcript_path: Path) -> str | None:
    """Best-effort: pull the last assistant text block out of a stream-json log."""
    last: str | None = None
    try:
        with transcript_path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event_obj: object = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event_obj, dict):
                    continue
                text = _extract_assistant_text(cast("dict[str, Any]", event_obj))
                if text:
                    last = text
    except FileNotFoundError:
        return None
    return last


def _extract_assistant_text(event: dict[str, Any]) -> str | None:
    # The Claude CLI stream-json schema is documented in the CLI README. We
    # accept a few shapes to stay robust across CLI versions.
    msg_obj: object = event.get("message")
    if isinstance(msg_obj, dict):
        msg = cast("dict[str, Any]", msg_obj)
        content_obj: object = msg.get("content")
        if isinstance(content_obj, list):
            content = cast("list[Any]", content_obj)
            chunks: list[str] = []
            for block_obj in content:
                if isinstance(block_obj, dict):
                    block = cast("dict[str, Any]", block_obj)
                    if block.get("type") == "text":
                        text_obj: object = block.get("text")
                        if isinstance(text_obj, str):
                            chunks.append(text_obj)
            if chunks:
                return "\n".join(chunks)
    if event.get("type") == "result":
        result_obj: object = event.get("result")
        if isinstance(result_obj, str):
            return result_obj
    return None


def _scrape_submission_fields(text: str) -> tuple[str | None, str | None, str | None]:
    """Pull (pr_url, branch, layer) out of an agent's final message via regex."""
    import re

    pr_url = None
    pr_match = re.search(r"https://github\.com/[^\s)]+/pull/\d+", text)
    if pr_match:
        pr_url = pr_match.group(0).rstrip(".,)")

    branch = None
    branch_match = re.search(r"\b(hackathon/[A-Za-z0-9._/-]+)", text)
    if branch_match:
        branch = branch_match.group(1)

    layer = None
    layer_match = re.search(
        r"\b(trust|identity|registry|transport|payments|negotiation|memory|coordination|"
        r"communication|privacy|auth|datafacts|policy)\b",
        text,
        re.IGNORECASE,
    )
    if layer_match:
        layer = layer_match.group(1).lower()

    return pr_url, branch, layer


def make_runner(transport: str, fixtures_dir: Path | None = None) -> AgentRunner:
    """Factory used by the CLI to keep `--dry-run` and live paths symmetric."""
    if transport == "claude-cli":
        return ClaudeCLIAgentRunner()
    if transport == "fixture":
        if fixtures_dir is None:
            fixtures_dir = Path(__file__).parent / "dry_run" / "fixtures"
        return FixtureAgentRunner(fixtures_dir=fixtures_dir)
    raise ValueError(f"unknown agent transport: {transport!r}")


def main(argv: Sequence[str] | None = None) -> int:
    """Tiny CLI mostly for debugging — `run_condition.py` is the real entrypoint."""
    import argparse

    parser = argparse.ArgumentParser(description="Spawn one agent (for debugging).")
    parser.add_argument("--transport", choices=["claude-cli", "fixture"], default="fixture")
    parser.add_argument("--cell-id", required=True)
    parser.add_argument("--run-idx", type=int, default=0)
    parser.add_argument("--model", default="opus")
    parser.add_argument("--brief", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--dry-run", action="store_true", help="Force fixture transport")
    args = parser.parse_args(argv)

    transport = "fixture" if args.dry_run else args.transport
    runner = make_runner(transport)
    brief_text = args.brief.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(brief_text.encode("utf-8")).hexdigest()[:16]
    spec = AgentSpawnSpec(
        cell_id=args.cell_id,
        run_idx=args.run_idx,
        model=args.model,
        brief_path=args.brief,
        brief_text=brief_text,
        prompt_hash=prompt_hash,
        seed=args.seed,
        workdir=args.workdir,
        timeout_seconds=args.timeout,
    )
    submission = runner.run(spec)
    json.dump(submission.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if submission.spawned and (submission.exit_code in (0, None)) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
