#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent
REWRITE_DIR = ROOT / "scripts" / "rewrite"
FULL_VECTORS = ROOT / "lifter" / "test_vectors" / "oracle_vectors_full_handlers.json"
DEFAULT_VECTORS = ROOT / "lifter" / "test_vectors" / "oracle_vectors.json"
IR_OUTPUT_DIR = ROOT.parent / "rewrite-regression-work" / "ir_outputs"
GOLDEN_HASHES_FILE = ROOT / "lifter" / "test_vectors" / "golden_ir_hashes.json"


def _run(argv: List[str], extra_env: Dict[str, str] | None = None) -> None:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    print("+", " ".join(argv))
    result = subprocess.run(argv, cwd=ROOT, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _run_cmd(script: Path, args: List[str] | None = None, extra_env: Dict[str, str] | None = None) -> None:
    _run(["cmd", "/c", str(script), *(args or [])], extra_env=extra_env)


def compute_ir_hashes(ir_dir: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if not ir_dir.is_dir():
        return hashes
    for ll_file in sorted(ir_dir.rglob("*.ll")):
        content = ll_file.read_text(encoding="utf-8", errors="replace")
        normalized = "\n".join(line.rstrip() for line in content.splitlines()) + "\n"
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        rel_key = ll_file.relative_to(ir_dir).as_posix()
        hashes[rel_key] = digest
    return dict(sorted(hashes.items()))


def check_determinism(ir_dir: Path, golden_file: Path) -> None:
    hashes = compute_ir_hashes(ir_dir)
    if not hashes:
        raise SystemExit(
            f"Determinism check FAILED — no .ll files found in {ir_dir}"
        )

    if not golden_file.exists():
        raise SystemExit(
            f"Determinism check FAILED — golden hash file is missing: {golden_file}. "
            "Run `python test.py update-golden` to regenerate it."
        )

    golden = json.loads(golden_file.read_text(encoding="utf-8"))
    mismatches: List[str] = []
    all_keys = sorted(set(golden) | set(hashes))
    for key in all_keys:
        expected = golden.get(key)
        actual = hashes.get(key)
        if expected != actual:
            mismatches.append(
                f"  {key}: expected={expected or '(missing)'} actual={actual or '(missing)'}"
            )
    if mismatches:
        print("Determinism check FAILED — mismatched files:")
        for m in mismatches:
            print(m)
        raise SystemExit(1)
    print(f"Determinism check passed: {len(hashes)} files match golden hashes")


def update_golden(ir_dir: Path, golden_file: Path) -> None:
    hashes = compute_ir_hashes(ir_dir)
    if not hashes:
        print("WARNING: no .ll files found in", ir_dir, "— nothing to write")
        return
    golden_file.parent.mkdir(parents=True, exist_ok=True)
    golden_file.write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
    print(f"Golden hashes updated: {golden_file} ({len(hashes)} files)")


def run_baseline() -> None:
    _run_cmd(REWRITE_DIR / "run.cmd")
    check_determinism(IR_OUTPUT_DIR, GOLDEN_HASHES_FILE)


def run_micro(filter_tokens: List[str], check_flags: bool, regenerate_oracle: bool) -> None:
    env: Dict[str, str] = {}
    if not regenerate_oracle:
        env["SKIP_ORACLE_GENERATION"] = "1"
    if check_flags:
        env["MERGEN_TEST_CHECK_FLAGS"] = "1"

    args: List[str] = []
    args.extend(filter_tokens)

    _run_cmd(REWRITE_DIR / "run_microtests.cmd", args=args, extra_env=env)

def run_full(check_flags: bool) -> None:
    env: Dict[str, str] | None = None
    if check_flags:
        env = {"MERGEN_TEST_CHECK_FLAGS": "1"}
    _run_cmd(REWRITE_DIR / "run_all_handlers.cmd", extra_env=env)

def run_flagstress(filter_tokens: List[str]) -> None:
    _run_cmd(REWRITE_DIR / "run_flagstress.cmd", args=filter_tokens)

def run_coverage(vectors_file: Path) -> None:
    rel = vectors_file.relative_to(ROOT) if vectors_file.is_absolute() else vectors_file
    _run_cmd(REWRITE_DIR / "collect_instruction_tests.cmd", args=["--vectors-file", str(rel)])


def run_report(vectors_file: Path, as_json: bool) -> None:
    args = ["--vectors", str(vectors_file)]
    if as_json:
        args.append("--json")
    _run([sys.executable, str(REWRITE_DIR / "report_coverage.py")] + args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convenience test runner for Mergen rewrite gates"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("quick", help="baseline + microtests (skip oracle regen)")
    sub.add_parser("baseline", help="run scripts/rewrite/run.cmd")
    sub.add_parser("update-golden", help="run baseline then regenerate golden IR hashes")
    full = sub.add_parser("full", help="run scripts/rewrite/run_all_handlers.cmd")
    full.add_argument(
        "--check-flags",
        action="store_true",
        help="enforce strict oracle flag comparisons during full-handler run",
    )
    coverage = sub.add_parser("coverage", help="run handler coverage report")
    coverage.add_argument(
        "--full",
        action="store_true",
        help="use full-handler vectors (oracle_vectors_full_handlers.json)",
    )
    coverage.add_argument(
        "--vectors",
        type=Path,
        default=None,
        help="explicit vectors file path",
    )

    micro = sub.add_parser("micro", help="run in-process instruction microtests")
    micro.add_argument("--check-flags", action="store_true", help="enable strict oracle flag checking")
    micro.add_argument(
        "--regen-oracle",
        action="store_true",
        help="regenerate oracle vectors before running",
    )
    micro.add_argument("filter", nargs="*", help="optional test name filter tokens")

    flags = sub.add_parser(
        "flags",
        help="generate expanded flag-stress vectors and run strict microtests",
    )
    flags.add_argument("filter", nargs="*", help="optional test name filter tokens")
    all_cmd = sub.add_parser("all", help="baseline + full-handler + full coverage")
    all_cmd.add_argument("--no-coverage", action="store_true", help="skip final coverage report")
    report_cmd = sub.add_parser("report", help="print handler test coverage report")
    report_cmd.add_argument("--json", action="store_true", help="output as JSON")
    report_cmd.add_argument("--vectors", type=Path, default=None, help="explicit vectors file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    command = args.command or "quick"

    if command == "baseline":
        run_baseline()
        return

    if command == "update-golden":
        _run_cmd(REWRITE_DIR / "run.cmd")
        update_golden(IR_OUTPUT_DIR, GOLDEN_HASHES_FILE)
        return

    if command == "micro":
        run_micro(args.filter, args.check_flags, args.regen_oracle)
        return

    if command == "full":
        run_full(args.check_flags)
        return

    if command == "coverage":
        if args.vectors is not None:
            vectors_file = args.vectors if args.vectors.is_absolute() else ROOT / args.vectors
        elif args.full:
            vectors_file = FULL_VECTORS
        else:
            vectors_file = DEFAULT_VECTORS

        if not vectors_file.exists():
            raise SystemExit(f"Vectors file does not exist: {vectors_file}")

        run_coverage(vectors_file)
        return

    if command == "report":
        if args.vectors is not None:
            vectors_file = args.vectors if args.vectors.is_absolute() else ROOT / args.vectors
        else:
            vectors_file = DEFAULT_VECTORS
        if not vectors_file.exists():
            raise SystemExit(f"Vectors file does not exist: {vectors_file}")
        run_report(vectors_file, args.json)
        return

    if command == "flags":
        run_flagstress(args.filter)
        return

    if command == "all":
        run_baseline()
        run_full(check_flags=True)
        if not args.no_coverage:
            run_coverage(FULL_VECTORS)
        return

    if command == "quick":
        run_baseline()
        run_micro([], check_flags=True, regenerate_oracle=False)
        return

    raise SystemExit(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
