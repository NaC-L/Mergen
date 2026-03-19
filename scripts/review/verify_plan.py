#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from review_buckets import (
    CheckCommand,
    bucket_order,
    bucket_paths,
    bucket_required_checks,
    load_changed_paths,
    normalize_path,
    required_checks_for_buckets,
)


@dataclass(frozen=True)
class PlannedCheck:
    command: CheckCommand
    buckets: list[str]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create or run targeted verification plan for PR changes")
    parser.add_argument("--base", default="main", help="Base revision")
    parser.add_argument("--head", default="HEAD", help="Head revision")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--paths",
        nargs="*",
        default=None,
        help="Optional explicit changed paths (bypasses git diff)",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Execute the planned checks in order",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop immediately when a check fails while running",
    )
    parser.add_argument(
        "--no-invariant-guard",
        action="store_true",
        help="Do not prepend scripts/review/invariant_guard.py to the run plan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output",
    )
    return parser.parse_args()


def _docs_only(paths: list[str]) -> bool:
    return bool(paths) and all(path.lower().endswith(".md") for path in paths)


def _build_plan(paths: list[str], include_invariant_guard: bool) -> list[PlannedCheck]:
    grouped = bucket_paths(paths)
    ordered_buckets = bucket_order(grouped.keys())

    check_sources: dict[str, list[str]] = {}
    for bucket in ordered_buckets:
        for check in bucket_required_checks(bucket):
            check_sources.setdefault(check.id, []).append(bucket)

    planned = [
        PlannedCheck(command=check, buckets=check_sources.get(check.id, []))
        for check in required_checks_for_buckets(ordered_buckets)
    ]

    if include_invariant_guard and paths and not _docs_only(paths):
        invariant_cmd = CheckCommand(
            id="invariant_guard",
            description="Run review invariant checks",
            argv=("python", "scripts/review/invariant_guard.py", "--paths", *paths),
        )
        planned.insert(0, PlannedCheck(command=invariant_cmd, buckets=ordered_buckets))

    return planned


def _run_plan(plan: list[PlannedCheck], repo_root: Path, fail_fast: bool) -> list[dict]:
    run_results: list[dict] = []

    for item in plan:
        cmd = list(item.command.argv)
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            run_results.append(
                {
                    "id": item.command.id,
                    "status": "BLOCKED",
                    "exit_code": None,
                    "buckets": item.buckets,
                    "command": item.command.shell_preview,
                    "stdout": "",
                    "stderr": str(exc),
                }
            )
            if fail_fast:
                break
            continue

        status = "PASS" if result.returncode == 0 else "FAIL"
        run_results.append(
            {
                "id": item.command.id,
                "status": status,
                "exit_code": result.returncode,
                "buckets": item.buckets,
                "command": item.command.shell_preview,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )

        if status == "FAIL" and fail_fast:
            break

    return run_results


def _plan_payload(paths: list[str], plan: list[PlannedCheck], run_results: list[dict] | None) -> dict:
    payload = {
        "total_files": len(paths),
        "docs_only": _docs_only(paths),
        "total_checks": len(plan),
        "checks": [
            {
                "id": item.command.id,
                "description": item.command.description,
                "command": item.command.shell_preview,
                "buckets": item.buckets,
            }
            for item in plan
        ],
    }

    if run_results is not None:
        payload["run_results"] = run_results
        payload["failed_checks"] = [entry["id"] for entry in run_results if entry["status"] == "FAIL"]
        payload["blocked_checks"] = [entry["id"] for entry in run_results if entry["status"] == "BLOCKED"]

    return payload


def _render_text(payload: dict) -> str:
    lines: list[str] = []
    lines.append(f"Changed files: {payload['total_files']}")
    lines.append(f"Docs only: {'yes' if payload['docs_only'] else 'no'}")
    lines.append(f"Planned checks: {payload['total_checks']}")
    lines.append("")

    if payload["checks"]:
        lines.append("Plan:")
        for check in payload["checks"]:
            bucket_scope = ", ".join(check["buckets"]) if check["buckets"] else "n/a"
            lines.append(f"- {check['id']}: {check['command']}")
            lines.append(f"  buckets: {bucket_scope}")
            lines.append(f"  reason: {check['description']}")
    else:
        lines.append("Plan: no checks required for this diff")

    if "run_results" in payload:
        lines.append("")
        lines.append("Execution:")
        for entry in payload["run_results"]:
            lines.append(f"- [{entry['status']}] {entry['id']} :: {entry['command']}")
            if entry.get("exit_code") is not None:
                lines.append(f"  exit_code: {entry['exit_code']}")
            if entry.get("stderr"):
                lines.append(f"  stderr: {entry['stderr'].strip()}")

        failed = payload.get("failed_checks", [])
        blocked = payload.get("blocked_checks", [])
        if failed or blocked:
            lines.append("")
            lines.append(
                "Verification run incomplete: "
                + ", ".join(
                    [
                        *(f"failed={name}" for name in failed),
                        *(f"blocked={name}" for name in blocked),
                    ]
                )
            )
        else:
            lines.append("")
            lines.append("Verification run passed")

    return "\n".join(lines)


def main() -> None:
    args = _parse_args()
    repo_root = args.repo_root.resolve()

    if args.paths:
        changed_paths = [normalize_path(path) for path in args.paths]
    else:
        changed_paths = load_changed_paths(repo_root, args.base, args.head)

    plan = _build_plan(changed_paths, include_invariant_guard=not args.no_invariant_guard)

    run_results = None
    if args.run:
        run_results = _run_plan(plan, repo_root=repo_root, fail_fast=args.fail_fast)

    payload = _plan_payload(changed_paths, plan, run_results)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(_render_text(payload))

    if run_results is not None:
        failed_or_blocked = [
            item for item in run_results if item["status"] in {"FAIL", "BLOCKED"}
        ]
        if failed_or_blocked:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
