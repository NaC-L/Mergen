#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
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
    chunk_paths,
    load_changed_paths,
    normalize_path,
    required_checks_for_buckets,
)


@dataclass(frozen=True)
class Shard:
    name: str
    files: list[str]
    description: str
    source_bucket: str
    risk: str
    required_checks: list[str]


def shard_paths(paths: list[str], max_files_per_shard: int = 5) -> list[Shard]:
    grouped = bucket_paths(paths)
    ordered_buckets = bucket_order(grouped.keys())

    shards: list[Shard] = []
    for bucket in ordered_buckets:
        files = grouped[bucket]
        chunks = chunk_paths(files, max_files_per_shard)
        checks = [check.id for check in bucket_required_checks(bucket)]
        risk = bucket_risk(bucket, files)

        for chunk_index, chunk in enumerate(chunks, start=1):
            suffix = "" if len(chunks) == 1 else f"_{chunk_index}"
            shards.append(
                Shard(
                    name=f"{bucket}{suffix}",
                    files=chunk,
                    description=bucket_description(bucket),
                    source_bucket=bucket,
                    risk=risk,
                    required_checks=checks,
                )
            )

    return shards


def build_payload(paths: list[str], max_files_per_shard: int) -> dict:
    shards = shard_paths(paths, max_files_per_shard=max_files_per_shard)
    bucket_names = [shard.source_bucket for shard in shards]
    required_checks = required_checks_for_buckets(bucket_names)

    return {
        "total_files": len(paths),
        "total_shards": len(shards),
        "max_files_per_shard": max_files_per_shard,
        "required_checks": [
            {
                "id": check.id,
                "description": check.description,
                "command": check.shell_preview,
            }
            for check in required_checks
        ],
        "shards": [asdict(shard) for shard in shards],
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shard PR changed files into review buckets")
    parser.add_argument("--base", default="main", help="Base revision")
    parser.add_argument("--head", default="HEAD", help="Head revision")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--max-files-per-shard",
        type=int,
        default=5,
        help="Split large buckets into shards of at most this many files",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        default=None,
        help="Optional explicit changed paths (bypasses git diff)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    repo_root = args.repo_root.resolve()
    if args.paths is not None:
        changed_paths = [normalize_path(path) for path in args.paths]
    else:
        changed_paths = load_changed_paths(repo_root, args.base, args.head)

    payload = build_payload(changed_paths, max_files_per_shard=args.max_files_per_shard)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
