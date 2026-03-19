#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import format_comment  # noqa: E402
import invariant_guard  # noqa: E402
import risk_map  # noqa: E402
import shard_pr  # noqa: E402
import verify_plan  # noqa: E402
from review_buckets import load_changed_paths, normalize_path  # noqa: E402


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Mergen review automation")
    parser.add_argument("--base", default="main", help="Base revision")
    parser.add_argument("--head", default="HEAD", help="Head revision")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "artifacts/review",
        help="Directory to write review artifacts",
    )
    parser.add_argument(
        "--max-files-per-shard",
        type=int,
        default=5,
        help="Maximum files per review shard",
    )
    parser.add_argument(
        "--run-verification",
        action="store_true",
        help="Execute planned verification commands",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        default=None,
        help="Optional explicit changed paths (bypasses git diff)",
    )
    return parser.parse_args()


def _invariant_result_to_dict(result: invariant_guard.CheckResult) -> dict[str, Any]:
    return {
        "id": result.id,
        "status": result.status,
        "files": result.files,
        "details": result.details,
    }


def _planned_check_to_dict(item: verify_plan.PlannedCheck) -> dict[str, Any]:
    return {
        "id": item.command.id,
        "description": item.command.description,
        "command": item.command.shell_preview,
        "buckets": item.buckets,
    }


def main() -> None:
    args = _parse_args()
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()

    # 1. Load changed paths
    if args.paths:
        changed_paths = [normalize_path(path) for path in args.paths]
    else:
        changed_paths = load_changed_paths(repo_root, args.base, args.head)

    # 2. Risk assessment
    risk_payload = risk_map.build_payload(changed_paths)

    # 3. PR sharding
    shard_payload = shard_pr.build_payload(
        changed_paths, max_files_per_shard=args.max_files_per_shard,
    )

    # 4. Invariant guard checks
    invariant_results = invariant_guard.run_invariant_guard(
        repo_root, changed_paths, run_all=False,
    )
    invariant_dicts = [_invariant_result_to_dict(r) for r in invariant_results]

    # 5. Verification plan (invariant guard already ran separately)
    plan = verify_plan._build_plan(changed_paths, include_invariant_guard=False)
    plan_dicts = [_planned_check_to_dict(item) for item in plan]

    # 6. Optionally execute verification
    verification_runs: list[dict[str, Any]] = []
    if args.run_verification:
        verification_runs = verify_plan._run_plan(
            plan, repo_root=repo_root, fail_fast=False,
        )

    # 7. Assemble review payload
    review_payload: dict[str, Any] = {
        "base": args.base,
        "head": args.head,
        "changed_files": changed_paths,
        "risk": risk_payload,
        "shards": shard_payload,
        "invariants": invariant_dicts,
        "verification_plan": plan_dicts,
        "verification_runs": verification_runs,
    }

    # 8. Render markdown
    comment_markdown = format_comment.build_markdown(review_payload)

    # 9. Write artifacts
    _write_json(output_dir / "risk_map.json", risk_payload)
    _write_json(output_dir / "shards.json", shard_payload)
    _write_json(output_dir / "invariants.json", invariant_dicts)
    _write_json(output_dir / "verification_plan.json", plan_dicts)
    if verification_runs:
        _write_json(output_dir / "verification_runs.json", verification_runs)
    _write_json(output_dir / "review.json", review_payload)
    comment_path = output_dir / "comment.md"
    comment_path.parent.mkdir(parents=True, exist_ok=True)
    comment_path.write_text(comment_markdown, encoding="utf-8")

    print(f"Wrote review artifacts to {output_dir}")
    print(f"- Changed files: {len(changed_paths)}")
    print(f"- Overall risk: {risk_payload['overall_risk']}")
    print(f"- Invariant checks: {len(invariant_results)}")
    print(f"- Verification checks: {len(plan_dicts)}")
    print(f"- Comment: {comment_path.as_posix()}")

    # 10. Exit code: 1 if any invariant FAIL or any verification run FAIL
    has_invariant_failure = any(r.status == "FAIL" for r in invariant_results)
    has_verification_failure = any(
        run.get("status") in {"FAIL", "BLOCKED"} for run in verification_runs
    )
    raise SystemExit(1 if has_invariant_failure or has_verification_failure else 0)


if __name__ == "__main__":
    main()
