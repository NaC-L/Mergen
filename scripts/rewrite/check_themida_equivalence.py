#!/usr/bin/env python3
"""Themida devirtualization semantic-equivalence check.

Premise: a virtualized function, after devirtualization, must call the same
external imports as its non-virtualized counterpart. Structural divergence in
the lifted IR (block count, SSA names, pass-ordering artifacts) is allowed;
semantic divergence at the import boundary is not.

For each entry in ``themida_samples.json``:
- lift the virtualized binary
- extract external call names from the resulting IR
- compare against the manifest's ``required_imports`` list
- fail hard on any required import that is absent

Use ``--update`` to regenerate ``required_imports`` from the reference binary.
Samples whose binaries are not present on disk are skipped, not failed, because
the binaries live outside the repository (``../testthemida/``) and are not
available in CI.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
LIFTER = ROOT / "build_iced" / "lifter.exe"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "themida_samples.json"
WORKROOT = ROOT.parent / "rewrite-regression-work" / "themida_ir"

# Matches a `call` that targets a named function:
#   %N = call i64 @GetStdHandle(...)
#   call void @"VirtualizerSDK64.dll#103"(...)
#   tail call ptr @foo(...)
# Captures the callee identifier (unquoted or the contents of the quotes).
_CALL_RE = re.compile(
    r'''^\s*(?:%\S+\s*=\s*)?(?:tail\s+|musttail\s+|notail\s+)?'''
    r'''call\s+\S+\s+@(?:"([^"]+)"|([A-Za-z_][\w.]*))\s*\(''',
    re.MULTILINE,
)


def _lift(binary: Path, entry: str, workdir: Path) -> Path:
    if not LIFTER.exists():
        raise SystemExit(
            f"Lifter not found: {LIFTER}. Build it with "
            "'cmd /c scripts\\dev\\build_iced.cmd' first."
        )
    if not binary.exists():
        raise SystemExit(f"Binary not found: {binary}")

    workdir.mkdir(parents=True, exist_ok=True)

    # Clear previous artifacts so a stale file can't mask a new failure.
    for stale in ("output.ll", "output_no_opts.ll", "output_diagnostics.json"):
        (workdir / stale).unlink(missing_ok=True)

    result = subprocess.run(
        [str(LIFTER), str(binary), entry],
        cwd=workdir,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=300,
    )
    ir_path = workdir / "output_no_opts.ll"
    if not ir_path.exists():
        tail_stdout = (result.stdout or "")[-600:]
        tail_stderr = (result.stderr or "")[-600:]
        raise SystemExit(
            f"Lifter did not emit output_no_opts.ll for {binary} @ {entry}\n"
            f"exit_code={result.returncode}\n"
            f"stdout-tail:\n{tail_stdout}\n"
            f"stderr-tail:\n{tail_stderr}"
        )
    return ir_path


# Lifter-synthesized helper names that appear as `call @<name>` in the IR but
# are not user imports — emitted by INT/UD2/syscall/segment-load lowering.
# Keeping this list close to the call extractor so it stays in sync with the
# semantics files that emit them (Semantics.ipp, Semantics_Misc.ipp, etc.).
_LIFTER_SYNTH_HELPERS = frozenset({
    "exception",       # INT1 / INT3 / UD2
    "fastfail",        # INT29
    "not_implemented", # many fallbacks (SCAS/REP, SYSCALL, etc.)
    "invalid",         # illegal-instruction path
    "loadGS",          # GS segment register read
    "loadDS",          # DS segment register read
    "pext",            # BMI2 PEXT pseudo-intrinsic
})


def _extract_call_names(ir_text: str) -> Dict[str, int]:
    """Return a multiset of call-target identifiers found in IR text.

    Intramodule calls to ``@main`` and outlined ``@sub_*`` thunks are excluded
    -- we only care about named external imports that the lifter resolved.
    Lifter-synthesized helper calls (``@exception``, ``@fastfail``, etc.) are
    also excluded so they do not surface as bogus "extra import" diffs.
    """
    counts: Dict[str, int] = {}
    for match in _CALL_RE.finditer(ir_text):
        name = match.group(1) or match.group(2)
        if not name:
            continue
        if name == "main" or name.startswith("sub_") or name.startswith("llvm."):
            continue
        if name in _LIFTER_SYNTH_HELPERS:
            continue
        counts[name] = counts.get(name, 0) + 1
    return counts


def _filter_imports(imports: Dict[str, int], ignore_patterns: List[str]) -> Dict[str, int]:
    if not ignore_patterns:
        return dict(imports)
    compiled = [re.compile(p) for p in ignore_patterns]
    return {k: v for k, v in imports.items() if not any(p.search(k) for p in compiled)}


def _diff(
    required: Set[str],
    actual: Dict[str, int],
) -> Tuple[List[str], bool]:
    lines: List[str] = []
    ok = True

    missing = sorted(required - set(actual))
    if missing:
        ok = False
        for name in missing:
            lines.append(f"  MISSING required import: @{name}")

    extra = sorted(set(actual) - required)
    # Extras are informational — a smarter devirtualizer may legitimately
    # surface additional imports. Never fatal.
    for name in extra:
        lines.append(f"  extra import (not required): @{name} x{actual[name]}")

    return lines, ok


def _check_sample(sample: dict) -> bool:
    name = sample["name"]
    virt_rel = sample["virt_binary"]
    virt = (ROOT / virt_rel).resolve()
    entry = sample["entry"]
    ignore = sample.get("ignore_imports", [])
    required = set(sample.get("required_imports", []))

    if not virt.exists():
        print(f"SKIP: {name} — virt binary not present at {virt}")
        return True

    if not required:
        print(
            f"FAIL: {name} — manifest has no required_imports; "
            f"run `python test.py themida --update` first."
        )
        return False

    ir_path = _lift(virt, entry, WORKROOT / name)
    ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
    actual = _filter_imports(_extract_call_names(ir_text), ignore)

    lines, ok = _diff(required, actual)
    summary = (
        f"{len(actual)} distinct imports, {sum(actual.values())} calls "
        f"(required {len(required)})"
    )
    if ok:
        print(f"PASS: {name} — {summary}")
        for line in lines:
            print(line)
    else:
        print(f"FAIL: {name} — {summary}")
        for line in lines:
            print(line)
        req_str = ", ".join(sorted(required)) or "(none)"
        act_str = ", ".join(f"{k}x{v}" for k, v in sorted(actual.items())) or "(none)"
        print(f"  required: {req_str}")
        print(f"  actual:   {act_str}")
    return ok


def _update_sample(sample: dict) -> dict:
    name = sample["name"]
    ref_rel = sample.get("reference_binary")
    entry = sample["entry"]
    ignore = sample.get("ignore_imports", [])

    if not ref_rel:
        print(f"SKIP update: {name} — no reference_binary in manifest")
        return sample

    ref = (ROOT / ref_rel).resolve()
    if not ref.exists():
        print(f"SKIP update: {name} — reference binary not present at {ref}")
        return sample

    ir_path = _lift(ref, entry, WORKROOT / f"{name}_reference")
    ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
    imports = _filter_imports(_extract_call_names(ir_text), ignore)

    updated = dict(sample)
    updated["required_imports"] = sorted(imports.keys())
    print(
        f"UPDATED {name}: {len(imports)} required imports from {ref.name} "
        f"({sum(imports.values())} total calls in reference)"
    )
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--update",
        action="store_true",
        help="regenerate required_imports from reference binaries",
    )
    parser.add_argument(
        "filter",
        nargs="*",
        help="only process samples whose name contains any of these tokens",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    all_samples = manifest["samples"]

    def matches(sample: dict) -> bool:
        return not args.filter or any(tok in sample["name"] for tok in args.filter)

    if args.update:
        manifest["samples"] = [
            _update_sample(s) if matches(s) else s for s in all_samples
        ]
        args.manifest.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Wrote {args.manifest}")
        return

    selected = [s for s in all_samples if matches(s)]
    if not selected:
        raise SystemExit("No samples matched filter")

    all_ok = True
    for s in selected:
        all_ok &= _check_sample(s)
    if not all_ok:
        raise SystemExit("Themida equivalence check FAILED")
    print("All Themida equivalence checks passed.")


if __name__ == "__main__":
    main()
