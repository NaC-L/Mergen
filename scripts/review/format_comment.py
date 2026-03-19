#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

_STATUS_ICON = {"PASS": "\u2705", "FAIL": "\u274c", "SKIP": "\u23ed\ufe0f"}


def _verdict(payload: dict[str, Any]) -> str:
    """Determine review verdict from invariant results and verification runs.

    FAIL in either → request_changes.  Otherwise → approve.
    """
    for result in payload.get("invariant_results", []):
        if str(result.get("status", "")).upper() == "FAIL":
            return "request_changes"
    for run in payload.get("verification_runs", []):
        if str(run.get("status", "")).upper() == "FAIL":
            return "request_changes"
    return "approve"


def build_markdown(payload: dict[str, Any]) -> str:
    """Render a full PR review comment from the orchestrator payload."""
    base = payload.get("base", "main")
    head = payload.get("head", "HEAD")
    changed_files: list[str] = payload.get("changed_files", [])
    diff_stat: str = payload.get("diff_stat", "")

    risk_map: dict[str, Any] = payload.get("risk_map", {})
    shards: dict[str, Any] = payload.get("shards", {})
    invariant_results: list[dict[str, Any]] = payload.get("invariant_results", [])
    verification_plan: list[dict[str, Any]] = payload.get("verification_plan", [])
    verification_runs: list[dict[str, Any]] = payload.get("verification_runs", [])

    overall_risk = risk_map.get("overall_risk", "P3")
    docs_only = risk_map.get("docs_only", False)
    verdict = _verdict(payload)

    lines: list[str] = []

    # -- Summary --
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Automated review for `{base}...{head}`")
    lines.append("")
    lines.append(f"- **Verdict:** {verdict}")
    lines.append(f"- **Changed files:** {len(changed_files)}")
    lines.append(f"- **Overall risk:** {overall_risk}")
    if diff_stat:
        lines.append(f"- **Diff stat:** `{diff_stat}`")
    if docs_only:
        lines.append("- **Docs-only PR** — no verification needed.")
    lines.append("")

    # -- Risk Map --
    buckets: list[dict[str, Any]] = risk_map.get("buckets", [])
    if buckets:
        sorted_buckets = sorted(
            buckets,
            key=lambda b: (_SEVERITY_ORDER.get(b.get("risk", "P3"), 9), b.get("name", "")),
        )
        lines.append("## Risk Map")
        lines.append("")
        lines.append("| Bucket | Risk | Files |")
        lines.append("|--------|------|------:|")
        for b in sorted_buckets:
            lines.append(f"| {b.get('name', '?')} | {b.get('risk', '?')} | {b.get('file_count', 0)} |")
        lines.append("")

    # -- Invariant Checks --
    if invariant_results:
        lines.append("## Invariant Checks")
        lines.append("")
        for res in invariant_results:
            status = str(res.get("status", "SKIP")).upper()
            icon = _STATUS_ICON.get(status, "\u2753")
            check_id = res.get("id", "unknown")
            lines.append(f"- {icon} **{check_id}**: {status}")
            for detail in res.get("details", []):
                lines.append(f"  - {detail}")
            for f in res.get("files", []):
                lines.append(f"  - `{f}`")
        lines.append("")

    # -- Verification Plan --
    if verification_plan:
        lines.append("## Verification Plan")
        lines.append("")
        for check in verification_plan:
            check_id = check.get("id", "?")
            desc = check.get("description", "")
            cmd = check.get("command", "")
            bucket_list = ", ".join(check.get("buckets", []))
            label = f"{check_id}: {desc}" if desc else check_id
            line = f"- **{label}** — `{cmd}`"
            if bucket_list:
                line += f" (buckets: {bucket_list})"
            lines.append(line)
        lines.append("")

    # -- Verification Execution --
    if verification_runs:
        lines.append("## Verification Execution")
        lines.append("")
        for run in verification_runs:
            status = str(run.get("status", "unknown")).upper()
            icon = _STATUS_ICON.get(status, "\u2753")
            cmd = run.get("command", "")
            run_id = run.get("id", "?")
            exit_code = run.get("exit_code")
            line = f"- {icon} **{run_id}**: {status}"
            if exit_code is not None:
                line += f" (exit {exit_code})"
            line += f" — `{cmd}`"
            lines.append(line)
        lines.append("")

    # -- Shards --
    shard_list: list[dict[str, Any]] = shards.get("shards", [])
    if shard_list:
        lines.append("## Shards")
        lines.append("")
        lines.append(f"Total shards: {shards.get('total_shards', len(shard_list))}")
        lines.append("")
        for s in shard_list:
            name = s.get("name", "?")
            risk = s.get("risk", "?")
            file_count = len(s.get("files", []))
            lines.append(f"- **{name}** ({risk}, {file_count} files): {s.get('description', '')}")
        lines.append("")

    # -- Artifacts --
    lines.append("## Artifacts")
    lines.append("")
    lines.append("- `artifacts/review/risk_map.json`")
    lines.append("- `artifacts/review/shards.json`")
    lines.append("- `artifacts/review/verification_plan.json`")
    lines.append("- `artifacts/review/invariants.json`")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render markdown review comment from review payload JSON",
    )
    parser.add_argument("--input", type=Path, required=True, help="Input review payload JSON")
    parser.add_argument("--out", type=Path, default=None, help="Optional output markdown path")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    markdown = build_markdown(payload)
    if args.out is not None:
        out_path = args.out.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")
        print(f"Wrote formatted comment to {out_path}")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
