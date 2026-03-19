#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from review_buckets import (
    bucket_description,
    bucket_order,
    bucket_paths,
    bucket_required_checks,
    bucket_risk,
    highest_risk,
    load_changed_paths,
    normalize_path,
    required_checks_for_buckets,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate risk map for a PR diff")
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
        "--json",
        action="store_true",
        help="Emit JSON payload (default emits plain text summary)",
    )
    return parser.parse_args()


def _is_docs_only(paths: list[str]) -> bool:
    return bool(paths) and all(path.lower().endswith(".md") for path in paths)


def build_payload(paths: list[str]) -> dict:
    grouped = bucket_paths(paths)
    ordered_buckets = bucket_order(grouped.keys())

    buckets_payload: list[dict] = []
    for bucket_name in ordered_buckets:
        files = grouped[bucket_name]
        checks = list(bucket_required_checks(bucket_name))
        buckets_payload.append(
            {
                "name": bucket_name,
                "description": bucket_description(bucket_name),
                "risk": bucket_risk(bucket_name, files),
                "file_count": len(files),
                "files": files,
                "required_checks": [
                    {
                        "id": check.id,
                        "description": check.description,
                        "command": check.shell_preview,
                    }
                    for check in checks
                ],
            }
        )

    overall_risk = highest_risk([entry["risk"] for entry in buckets_payload])
    required_checks = required_checks_for_buckets(ordered_buckets)
    has_unassigned = "unassigned" in grouped

    risk_counts: dict[str, int] = {}
    for entry in buckets_payload:
        risk = entry["risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {
        "total_files": len(paths),
        "total_buckets": len(buckets_payload),
        "docs_only": _is_docs_only(paths),
        "overall_risk": overall_risk,
        "manual_review_required": has_unassigned,
        "risk_bucket_counts": risk_counts,
        "required_checks": [
            {
                "id": check.id,
                "description": check.description,
                "command": check.shell_preview,
            }
            for check in required_checks
        ],
        "buckets": buckets_payload,
    }


def _render_text(payload: dict) -> str:
    lines: list[str] = []
    lines.append(f"Overall risk: {payload['overall_risk']}")
    lines.append(f"Changed files: {payload['total_files']}")
    lines.append(f"Buckets: {payload['total_buckets']}")
    lines.append(f"Docs only: {'yes' if payload['docs_only'] else 'no'}")
    if payload["manual_review_required"]:
        lines.append("Manual review required: yes (unassigned paths present)")
    else:
        lines.append("Manual review required: no")

    lines.append("")
    lines.append("Buckets:")
    for bucket in payload["buckets"]:
        lines.append(f"- [{bucket['risk']}] {bucket['name']} ({bucket['file_count']} files)")
        lines.append(f"  {bucket['description']}")
        for file_path in bucket["files"]:
            lines.append(f"    - {file_path}")
        if bucket["required_checks"]:
            lines.append("  Required checks:")
            for check in bucket["required_checks"]:
                lines.append(f"    - {check['id']}: {check['command']}")

    lines.append("")
    lines.append("Aggregate required checks:")
    if payload["required_checks"]:
        for check in payload["required_checks"]:
            lines.append(f"- {check['id']}: {check['command']}")
    else:
        lines.append("- none")

    return "\n".join(lines)


def main() -> None:
    args = _parse_args()
    repo_root = args.repo_root.resolve()

    if args.paths:
        changed_paths = [normalize_path(path) for path in args.paths]
    else:
        changed_paths = load_changed_paths(repo_root, args.base, args.head)

    payload = build_payload(changed_paths)
    if args.json:
        print(json.dumps(payload, indent=2))
        return

    print(_render_text(payload))


if __name__ == "__main__":
    main()
