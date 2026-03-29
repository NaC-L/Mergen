#!/usr/bin/env python3
"""Runtime semantic regression for all lifted samples.

Reads semantic test cases from instruction_microtests.json, generates
lli-executable wrapper modules for each sample, and verifies that the
lifted IR computes correct return values for all declared inputs.

This replaces the single-sample check_calc_jumptable_semantic.py with
coverage across every sample that declares a ``semantic`` field.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
REWRITE_DIR = ROOT / "scripts" / "rewrite"
MANIFEST_PATH = REWRITE_DIR / "instruction_microtests.json"
DEFAULT_IR_DIR = ROOT.parent / "rewrite-regression-work" / "ir_outputs"

# Hardcoded fallback parameter list for lifted functions that haven't been
# minimized. After PrototypeMinimizationPass, signatures are parsed from IR.
LIFTED_PARAMS_FULL: List[Tuple[str, str]] = [
    ("i64", "RAX"),  ("i64", "RCX"),  ("i64", "RDX"),  ("i64", "RBX"),
    ("i64", "RSP"),  ("i64", "RBP"),  ("i64", "RSI"),  ("i64", "RDI"),
    ("i64", "R8"),   ("i64", "R9"),   ("i64", "R10"),  ("i64", "R11"),
    ("i64", "R12"),  ("i64", "R13"),  ("i64", "R14"),  ("i64", "R15"),
    ("ptr", "EIP"),  ("ptr", "memory"),
    ("i128", "XMM0"),  ("i128", "XMM1"),  ("i128", "XMM2"),  ("i128", "XMM3"),
    ("i128", "XMM4"),  ("i128", "XMM5"),  ("i128", "XMM6"),  ("i128", "XMM7"),
    ("i128", "XMM8"),  ("i128", "XMM9"),  ("i128", "XMM10"), ("i128", "XMM11"),
    ("i128", "XMM12"), ("i128", "XMM13"), ("i128", "XMM14"), ("i128", "XMM15"),
]

# Regex to extract parameter list from a define line.
# Handles optional linkage/visibility keywords (dso_local, etc.) and attributes.
# Examples matched:
#   define i64 @main(i64 %RCX) {
#   define dso_local i64 @main(i64 %RCX) local_unnamed_addr #0 {
#   define i64 @main() {
_DEFINE_RE = re.compile(
    r'^define\s+.*?@main\((.*?)\)\s*(?:local_unnamed_addr\s*)?(?:#\d+\s*)?\{',
    re.MULTILINE,
)


def _parse_params_from_ir(ir_text: str) -> List[Tuple[str, str]]:
    """Parse the actual function parameter list from the IR define line.

    Returns a list of (type, name) tuples.  Falls back to the full 34-param
    list if parsing fails (e.g. un-minimized IR from an older lifter build).
    """
    m = _DEFINE_RE.search(ir_text)
    if not m:
        return LIFTED_PARAMS_FULL

    raw_params = m.group(1)
    if not raw_params.strip():
        return []

    result: List[Tuple[str, str]] = []
    for param in raw_params.split(","):
        param = param.strip()
        if not param:
            continue
        # Strip attributes like 'nocapture readnone' that appear between type and name.
        # Pattern: type [attrs...] %name
        # Examples: 'i64 %RCX', 'ptr nocapture readnone %EIP', 'i128 %XMM0'
        parts = param.split()
        ty = parts[0]  # first token is the type
        # Find the %name token (last token starting with %)
        name = None
        for tok in reversed(parts):
            if tok.startswith("%"):
                name = tok[1:]  # strip the % prefix
                break
        if name is None:
            # Unnamed parameter -- shouldn't happen with our lifter, fallback.
            return LIFTED_PARAMS_FULL
        result.append((ty, name))
    return result

# Pre-compiled pattern for stores to inttoptr addresses.  These are dead
# stores to original-binary stack locations that would segfault lli.
_INTTOPTR_STORE_RE = re.compile(
    r"^\s*store\s+.*inttoptr\s*\(.*\)\s*,.*$", re.MULTILINE
)

# Calls to inttoptr targets (outlined calls to concrete addresses).
# These would segfault in lli. The call results are unused by the
# return value computation, so stripping them is safe for semantic checks.
_INTTOPTR_CALL_RE = re.compile(
    r"^\s*(%\S+\s*=\s*)?(?:tail\s+)?call\s+.*inttoptr\s*\(.*\).*$", re.MULTILINE
)


# ---------------------------------------------------------------------------
# lli discovery (mirrors logic from the old single-sample checker)
# ---------------------------------------------------------------------------

def _find_lli() -> Path:
    explicit = os.environ.get("MERGEN_LLI_EXE")
    if explicit:
        candidate = Path(explicit)
        if candidate.exists():
            return candidate

    which_hit = shutil.which("lli.exe") or shutil.which("lli")
    if which_hit:
        return Path(which_hit)

    candidates: List[Path] = []

    llvm_bin_env = os.environ.get("MERGEN_LLVM_BIN")
    if llvm_bin_env:
        llvm_bin = Path(llvm_bin_env)
        candidates.extend([llvm_bin / "lli.exe", llvm_bin / "lli"])

    llvm_dir_env = os.environ.get("LLVM_DIR")
    if llvm_dir_env:
        llvm_dir = Path(llvm_dir_env)
        for base in [llvm_dir, *llvm_dir.parents[:5]]:
            candidates.extend([base / "bin" / "lli.exe", base / "bin" / "lli"])

    candidates.extend([
        ROOT.parent / "llvm18-install" / "bin" / "lli.exe",
        ROOT.parent / "llvm18-install" / "bin" / "lli",
        ROOT.parent / "llvm18-build" / "bin" / "lli.exe",
        ROOT.parent / "llvm18-build" / "bin" / "lli",
        ROOT.parent / "llvm-project-18.1.0" / "build" / "bin" / "lli.exe",
        ROOT.parent / "llvm-project-18.1.0" / "build" / "bin" / "lli",
    ])

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise SystemExit(
        "Could not find LLVM lli executable. "
        "Set MERGEN_LLI_EXE or add LLVM bin directory to PATH."
    )


# ---------------------------------------------------------------------------
# IR manipulation
# ---------------------------------------------------------------------------

def _strip_inttoptr_stores(ir_text: str) -> str:
    """Remove ``store ... inttoptr(...)`` and ``call inttoptr(...)`` instructions.

    The lifter emits stores of function arguments to the original binary's
    stack addresses and calls to outlined functions at concrete addresses.
    These addresses are not mapped in lli and would segfault.
    The stores and calls are provably dead — the return value never reads
    from these fixed addresses or depends on call results.
    """
    cleaned = _INTTOPTR_STORE_RE.sub("", ir_text)
    return _INTTOPTR_CALL_RE.sub("", cleaned)


def _rename_entry(ir_text: str, new_name: str) -> str:
    """Rename ``@main`` to ``@<new_name>`` throughout the IR module."""
    # Replace the definition and any internal references.
    return ir_text.replace("@main(", f"@{new_name}(")


def _build_call_args(inputs: Dict[str, int], params: List[Tuple[str, str]]) -> str:
    """Build the LLVM IR argument list for calling the lifted function.

    Uses the actual parameter list parsed from the IR, not a hardcoded list.
    """
    parts: List[str] = []
    for ty, name in params:
        if ty == "ptr":
            parts.append("ptr null")
        else:
            value = inputs.get(name, 0)
            parts.append(f"{ty} {value}")
    return ", ".join(parts)


def _generate_wrapper(fn_name: str, cases: List[dict], params: List[Tuple[str, str]]) -> str:
    """Generate ``@semantic_main`` that asserts every test case."""
    lines: List[str] = ["", "define i32 @semantic_main() {", "entry:"]

    for idx, case in enumerate(cases):
        inputs: Dict[str, int] = case.get("inputs", {})
        expected: int = case["expected"]
        label = f"case{idx}"

        if idx == 0:
            lines.append(f"  br label %{label}")
        lines.append("")
        lines.append(f"{label}:")
        call_args = _build_call_args(inputs, params)
        lines.append(f"  %ret{idx} = call i64 @{fn_name}({call_args})")
        lines.append(f"  %ok{idx} = icmp eq i64 %ret{idx}, {expected}")
        next_label = "pass" if idx == len(cases) - 1 else f"case{idx + 1}"
        lines.append(f"  br i1 %ok{idx}, label %{next_label}, label %fail{idx}")

    lines.append("")
    for idx in range(len(cases)):
        lines.append(f"fail{idx}:")
        lines.append(f"  ret i32 {idx + 1}")
        lines.append("")

    lines.append("pass:")
    lines.append("  ret i32 0")
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-sample runner
# ---------------------------------------------------------------------------

def _run_sample(
    name: str,
    cases: List[dict],
    ir_dir: Path,
    lli_path: Path,
    *,
    input_ir: Optional[Path] = None,
) -> Tuple[bool, str]:
    """Run semantic check for one sample.  Returns ``(passed, detail)``."""
    ir_file = input_ir or (ir_dir / f"{name}.ll")
    if not ir_file.exists():
        return False, f"IR file not found: {ir_file}"

    base_ir = ir_file.read_text(encoding="utf-8", errors="replace")

    # Verify the IR contains a @main definition we can rename.
    if "@main(" not in base_ir:
        return False, "IR does not contain @main function"

    cleaned = _strip_inttoptr_stores(base_ir)
    params = _parse_params_from_ir(cleaned)
    fn_name = f"lifted_{name}"
    renamed = _rename_entry(cleaned, fn_name)
    wrapper = _generate_wrapper(fn_name, cases, params)

    semantic_path = ir_dir / f"{name}_semantic.ll"
    semantic_path.parent.mkdir(parents=True, exist_ok=True)
    semantic_path.write_text(
        renamed.rstrip() + "\n" + wrapper + "\n", encoding="utf-8"
    )

    cmd = [str(lli_path), "--entry-function=semantic_main", str(semantic_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "lli timed out (30s)"

    if result.returncode == 0:
        return True, f"{len(cases)} cases passed"

    # Decode which case failed.
    if 1 <= result.returncode <= len(cases):
        c = cases[result.returncode - 1]
        inputs = c.get("inputs", {})
        expected = c["expected"]
        label = c.get("label", "")
        msg = f"case {result.returncode}/{len(cases)} failed"
        if inputs:
            msg += f" inputs={inputs}"
        msg += f" expected={expected}"
        if label:
            msg += f" ({label})"
        return False, msg

    # lli crash or unexpected exit.
    stderr = (result.stderr or "").strip()[:200]
    return False, f"lli exited with code {result.returncode}" + (
        f": {stderr}" if stderr else ""
    )


# ---------------------------------------------------------------------------
# Manifest loading and validation
# ---------------------------------------------------------------------------

def _load_semantic_samples(
    manifest_path: Path,
    filters: Sequence[str],
) -> List[Tuple[str, List[dict]]]:
    """Return ``[(name, cases)]`` for all non-skipped samples with semantic
    test cases, optionally filtered by name substrings."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result: List[Tuple[str, List[dict]]] = []

    for sample in manifest["samples"]:
        if sample.get("skip"):
            continue
        if sample.get("ci_skip") and os.environ.get("CI"):
            continue
        cases = sample.get("semantic")
        if not cases:
            continue
        name = sample["name"]
        if filters and not any(f in name for f in filters):
            continue

        # Validate each case.
        for idx, case in enumerate(cases):
            if "expected" not in case:
                raise SystemExit(
                    f"sample '{name}' semantic case {idx}: missing 'expected'"
                )
            if not isinstance(case["expected"], int):
                raise SystemExit(
                    f"sample '{name}' semantic case {idx}: "
                    f"'expected' must be int, got {type(case['expected']).__name__}"
                )
            inputs = case.get("inputs", {})
            if not isinstance(inputs, dict):
                raise SystemExit(
                    f"sample '{name}' semantic case {idx}: "
                    f"'inputs' must be object, got {type(inputs).__name__}"
                )

        result.append((name, cases))

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_all(
    ir_dir: Path = DEFAULT_IR_DIR,
    manifest: Path = MANIFEST_PATH,
    filters: Optional[List[str]] = None,
    input_ir: Optional[Path] = None,
) -> int:
    """Run semantic checks.  Returns the number of failures."""
    samples = _load_semantic_samples(manifest, filters or [])
    if not samples:
        print("No samples with semantic cases matched the filter.")
        return 0

    lli_path = _find_lli()
    print(f"Using lli: {lli_path}")

    passed = 0
    failed = 0
    failures: List[str] = []

    for name, cases in samples:
        override = input_ir if (input_ir and len(samples) == 1) else None
        ok, detail = _run_sample(name, cases, ir_dir, lli_path, input_ir=override)
        status = "  OK  " if ok else " FAIL "
        print(f"[{status}] {name}: {detail}")
        if ok:
            passed += 1
        else:
            failed += 1
            failures.append(f"  {name}: {detail}")

    total = passed + failed
    print(f"\nSemantic regression: {passed}/{total} passed")
    if failures:
        print("Failures:")
        for f in failures:
            print(f)
    return failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Runtime semantic regression for all lifted samples via lli"
    )
    parser.add_argument("--ir-dir", type=Path, default=DEFAULT_IR_DIR)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--filter", nargs="*", default=[],
                        help="sample name substrings to include")
    parser.add_argument("--input-ir", type=Path, default=None,
                        help="override IR file (use with a single --filter)")
    args = parser.parse_args()

    failures = run_all(
        ir_dir=args.ir_dir,
        manifest=args.manifest,
        filters=args.filter,
        input_ir=args.input_ir,
    )
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
