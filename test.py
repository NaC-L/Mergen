#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent
REWRITE_DIR = ROOT / "scripts" / "rewrite"
FULL_VECTORS = ROOT / "lifter" / "test" / "test_vectors" / "oracle_vectors_full_handlers.json"
DEFAULT_VECTORS = ROOT / "lifter" / "test" / "test_vectors" / "oracle_vectors.json"
IR_OUTPUT_DIR = ROOT.parent / "rewrite-regression-work" / "ir_outputs"
GOLDEN_HASHES_FILE = ROOT / "lifter" / "test" / "test_vectors" / "golden_ir_hashes.json"
SEMANTIC_SCRIPT = REWRITE_DIR / "check_semantic.py"


def _run(argv: List[str], extra_env: Dict[str, str] | None = None) -> None:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    print("+", " ".join(argv))
    result = subprocess.run(argv, cwd=ROOT, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _run_capture(
    argv: List[str],
    *,
    cwd: Path | None = None,
    extra_env: Dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    cmd = [str(arg) for arg in argv]
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def _assert_failure_contains(
    result: subprocess.CompletedProcess[str],
    *,
    check_name: str,
    required_substrings: List[str],
) -> None:
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        raise SystemExit(
            f"Negative check '{check_name}' unexpectedly succeeded. Output:\n{output}"
        )

    missing = [token for token in required_substrings if token not in output]
    if missing:
        raise SystemExit(
            f"Negative check '{check_name}' failed to emit required markers {missing}. "
            f"Output:\n{output}"
        )

    print(f"[OK] {check_name}")


def _run_cmd(script: Path, args: List[str] | None = None, extra_env: Dict[str, str] | None = None) -> None:
    _run(["cmd", "/c", str(script), *(args or [])], extra_env=extra_env)


def _resolve_repo_path(user_path: Path, label: str) -> Path:
    resolved_root = ROOT.resolve()
    resolved_path = (user_path if user_path.is_absolute() else ROOT / user_path).resolve()

    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise SystemExit(
            f"{label} must be inside repository root '{resolved_root}', got '{resolved_path}'"
        ) from exc

    return resolved_path


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
    # Only check files tracked in the golden set.  C-compiled samples produce
    # toolchain-dependent IR (different addresses) and are excluded from golden
    # tracking — their correctness is validated by semantic tests instead.
    for key in sorted(golden):
        expected = golden[key]
        actual = hashes.get(key)
        if expected != actual:
            mismatches.append(
                f"  {key}: expected={expected} actual={actual or '(missing)'}"
            )
    if mismatches:
        print("Determinism check FAILED — mismatched files:")
        for m in mismatches:
            print(m)
        raise SystemExit(1)
    unchecked = sorted(set(hashes) - set(golden))
    checked = len(golden)
    print(f"Determinism check passed: {checked} golden files match", end="")
    if unchecked:
        print(f" ({len(unchecked)} untracked files skipped)")
    else:
        print()


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
    vectors_arg = vectors_file.relative_to(ROOT)
    _run_cmd(REWRITE_DIR / "collect_instruction_tests.cmd", args=["--vectors-file", str(vectors_arg)])


def run_report(vectors_file: Path, as_json: bool) -> None:
    args = ["--vectors", str(vectors_file)]
    if as_json:
        args.append("--json")
    _run([sys.executable, str(REWRITE_DIR / "report_coverage.py")] + args)


def run_semantic(filters: List[str] | None = None, input_ir: Path | None = None) -> None:
    args = [sys.executable, str(SEMANTIC_SCRIPT), "--ir-dir", str(IR_OUTPUT_DIR)]
    if filters:
        args.extend(["--filter"] + filters)
    if input_ir is not None:
        args.extend(["--input-ir", str(input_ir)])
    _run(args)


def run_negative_checks() -> None:
    lifter_path = ROOT / "build_iced" / "lifter.exe"
    if not lifter_path.exists():
        raise SystemExit(
            f"Negative checks require a built lifter at '{lifter_path}'. "
            "Run `cmd /c scripts\\dev\\build_iced.cmd` first."
        )

    no_args_result = _run_capture(["cmd", "/c", str(lifter_path)])
    _assert_failure_contains(
        no_args_result,
        check_name="lifter rejects missing positional args",
        required_substrings=["Usage:"],
    )

    rewrite_workdir = ROOT.parent / "rewrite-regression-work"
    verify_script = REWRITE_DIR / "verify.ps1"

    with tempfile.TemporaryDirectory(prefix="mergen-negative-") as temp_dir:
        temp_root = Path(temp_dir)

        bad_name_manifest = temp_root / "bad_manifest_name.json"
        bad_name_manifest.write_text(
            json.dumps({"samples": [{"name": "..\\\\evil", "patterns": ["ret"]}]}, indent=2),
            encoding="utf-8",
        )
        bad_name_result = _run_capture(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(verify_script),
                "-WorkDir",
                str(rewrite_workdir),
                "-ManifestPath",
                str(bad_name_manifest),
            ]
        )
        _assert_failure_contains(
            bad_name_result,
            check_name="verify rejects path-traversal manifest sample name",
            required_substrings=["invalid name", "path traversal"],
        )

        bad_patterns_manifest = temp_root / "bad_manifest_patterns.json"
        bad_patterns_manifest.write_text(
            json.dumps({"samples": [{"name": "branch", "patterns": "ret"}]}, indent=2),
            encoding="utf-8",
        )
        bad_patterns_result = _run_capture(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(verify_script),
                "-WorkDir",
                str(rewrite_workdir),
                "-ManifestPath",
                str(bad_patterns_manifest),
            ]
        )
        _assert_failure_contains(
            bad_patterns_result,
            check_name="verify rejects string patterns descriptors",
            required_substrings=["patterns must be an array"],
        )

        bad_vectors_path = temp_root / "bad_vectors_skip.json"
        bad_vectors_path.write_text(
            json.dumps(
                {"cases": [{"name": "x", "handler": "add", "skip": "false"}]},
                indent=2,
            ),
            encoding="utf-8",
        )
        bad_vectors_result = _run_capture(
            [
                sys.executable,
                str(REWRITE_DIR / "collect_instruction_tests.py"),
                "--vectors-file",
                str(bad_vectors_path),
                "--json",
            ]
        )
        _assert_failure_contains(
            bad_vectors_result,
            check_name="coverage collector rejects non-boolean skip values",
            required_substrings=["invalid 'skip' value", "expected boolean"],
        )

    outside_repo_vectors_result = _run_capture(
        [
            sys.executable,
            str(ROOT / "test.py"),
            "coverage",
            "--vectors",
            "C:/Windows/win.ini",
        ]
    )
    _assert_failure_contains(
        outside_repo_vectors_result,
        check_name="test runner rejects vectors paths outside repository",
        required_substrings=["must be inside repository root"],
    )

    print("Negative checks passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convenience test runner for Mergen rewrite gates"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("quick", help="baseline + microtests (skip oracle regen)")
    sub.add_parser("baseline", help="run scripts/rewrite/run.cmd")
    sub.add_parser("update-golden", help="run baseline then regenerate golden IR hashes")
    sub.add_parser("negative", help="run explicit negative/failure contract checks")
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
    semantic = sub.add_parser("semantic", help="run runtime semantic regression for all samples")
    semantic.add_argument("--input-ir", type=Path, default=None, help="override IR file (single sample)")
    semantic.add_argument("filter", nargs="*", help="optional sample name filter tokens")
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

    if command == "negative":
        run_negative_checks()
        return

    if command == "micro":
        run_micro(args.filter, args.check_flags, args.regen_oracle)
        return

    if command == "full":
        run_full(args.check_flags)
        return

    if command == "coverage":
        if args.vectors is not None:
            vectors_file = _resolve_repo_path(args.vectors, "Coverage vectors path")
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
            vectors_file = _resolve_repo_path(args.vectors, "Report vectors path")
        else:
            vectors_file = DEFAULT_VECTORS
        if not vectors_file.exists():
            raise SystemExit(f"Vectors file does not exist: {vectors_file}")
        run_report(vectors_file, args.json)
        return

    if command == "semantic":
        run_semantic(args.filter, args.input_ir)
        return


    if command == "flags":
        run_flagstress(args.filter)
        return

    if command == "all":
        run_baseline()
        run_semantic()
        run_full(check_flags=True)
        if not args.no_coverage:
            run_coverage(FULL_VECTORS)
        return

    if command == "quick":
        run_baseline()
        run_semantic()
        run_micro([], check_flags=True, regenerate_oracle=False)
        return

    raise SystemExit(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
