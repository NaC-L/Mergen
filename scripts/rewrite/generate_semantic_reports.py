#!/usr/bin/env python3
"""Per-sample semantic equivalence reports.

For every non-skipped sample in ``instruction_microtests.json`` this script:

1. Loads the lifted+optimized IR from ``rewrite-regression-work/ir_outputs/<name>.ll``.
2. Strips dead inttoptr stores/calls and rewrites ``@main`` -> ``@lifted_<name>`` so
   the module is loadable by ``lli``.
3. Runs every ``semantic`` case from the manifest through ``lli`` individually so
   each case yields its own pass/fail.
4. Writes ``docs/semantic_reports/<name>.md`` summarising the source, the lifted IR
   metadata, the per-case results, and the overall verdict.
5. Writes ``docs/semantic_reports/INDEX.md`` with a roll-up across every sample.

This reuses the IR-massaging primitives in ``check_semantic.py`` so the report
numbers match what ``python test.py semantic`` would report.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MERGEN = Path(__file__).resolve().parents[2]
ROOT = MERGEN.parent
SCRIPT_DIR = MERGEN / "scripts" / "rewrite"
SOURCE_DIR = MERGEN / "testcases" / "rewrite_smoke"
MANIFEST = SCRIPT_DIR / "instruction_microtests.json"
DEFAULT_IR_DIR = ROOT / "rewrite-regression-work" / "ir_outputs"
REPORT_DIR = MERGEN / "docs" / "semantic_reports"

sys.path.insert(0, str(SCRIPT_DIR))
import check_semantic as cs  # noqa: E402

SOURCE_EXTS = (".c", ".cpp", ".asm")


def _find_source(name: str) -> Optional[Path]:
    for ext in SOURCE_EXTS:
        candidate = SOURCE_DIR / f"{name}{ext}"
        if candidate.exists():
            return candidate
    return None


def _read_source_snippet(path: Path, max_lines: int = 120) -> Tuple[str, bool]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    truncated = len(lines) > max_lines
    if truncated:
        lines = lines[:max_lines]
    return "\n".join(lines), truncated


def _ir_summary(ir_text: str) -> Dict[str, object]:
    fn_count = ir_text.count("\ndefine ")
    if ir_text.startswith("define "):
        fn_count += 1
    return {"lines": ir_text.count("\n") + 1, "functions": fn_count}


def _run_one_case(
    fn_name: str,
    cleaned_ir: str,
    params: List[Tuple[str, str]],
    case: dict,
    semantic_path: Path,
    lli: Path,
) -> Tuple[bool, str, str]:
    """Run a single case via lli; return (ok, actual_or_error, raw_stderr)."""
    inputs = case.get("inputs", {})
    expected = case["expected"]
    renamed = cleaned_ir.replace("@main(", f"@{fn_name}(")
    args = cs._build_call_args(inputs, params)

    cmp_wrapper = "\n".join(
        [
            "",
            "define i32 @semantic_cmp() {",
            "entry:",
            f"  %ret = call i64 @{fn_name}({args})",
            f"  %ok = icmp eq i64 %ret, {expected}",
            "  br i1 %ok, label %pass, label %fail",
            "pass:",
            "  ret i32 0",
            "fail:",
            "  ret i32 1",
            "}",
            "",
        ]
    )
    semantic_path.write_text(renamed.rstrip() + "\n" + cmp_wrapper, encoding="utf-8")
    cmd = [str(lli), "--entry-function=semantic_cmp", str(semantic_path)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "lli timed out (30s)", ""

    if r.returncode == 0:
        return True, str(expected), ""

    if r.returncode == 1:
        # Rerun with low32 wrapper to surface the actual lifted result.
        low_wrapper = "\n".join(
            [
                "",
                "define i32 @semantic_low() {",
                "entry:",
                f"  %ret = call i64 @{fn_name}({args})",
                "  %low = trunc i64 %ret to i32",
                "  ret i32 %low",
                "}",
                "",
            ]
        )
        semantic_path.write_text(
            renamed.rstrip() + "\n" + low_wrapper, encoding="utf-8"
        )
        cmd2 = [str(lli), "--entry-function=semantic_low", str(semantic_path)]
        try:
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
            actual = f"{r2.returncode} (low32)"
        except subprocess.TimeoutExpired:
            actual = "timeout"
        return False, actual, (r.stderr or "").strip()[:300]

    err = (r.stderr or "").strip().splitlines()
    msg = err[0] if err else f"exit {r.returncode}"
    return False, f"crash ({msg})", "\n".join(err)[:600]


def _format_inputs(inputs: Dict[str, int]) -> str:
    if not inputs:
        return "_(none)_"
    return ", ".join(f"{k}={v}" for k, v in inputs.items())


def _write_report(
    sample: dict,
    source: Optional[Path],
    ir_path: Path,
    ir_stats: Dict[str, object],
    rows: List[dict],
    out_path: Path,
) -> None:
    name = sample["name"]
    symbol = sample.get("symbol", "")
    total = len(rows)
    passed = sum(1 for r in rows if r["ok"])
    failed = total - passed
    if total == 0:
        verdict = "N/A (no semantic cases declared)"
    elif failed == 0:
        verdict = "PASS"
    else:
        verdict = f"FAIL ({failed}/{total})"

    lines: List[str] = []
    lines.append(f"# {name} - semantic equivalence")
    lines.append("")
    lines.append(f"- **Verdict:** {verdict}")
    lines.append(f"- **Cases:** {passed}/{total} passed")
    if source is not None:
        rel_src = source.relative_to(MERGEN).as_posix()
        lines.append(f"- **Source:** `{rel_src}`")
    else:
        lines.append("- **Source:** _(not found in testcases/rewrite_smoke)_")
    rel_ir = ir_path.relative_to(ROOT).as_posix() if ir_path.exists() else "(missing)"
    lines.append(f"- **Lifted IR:** `{rel_ir}`")
    lines.append(f"- **Symbol:** `{symbol}`")
    lines.append(
        f"- **IR size:** {ir_stats.get('lines', '?')} lines, "
        f"{ir_stats.get('functions', '?')} function definitions"
    )
    lines.append("")
    lines.append("## Semantic cases")
    lines.append("")
    lines.append("| # | Inputs | Expected | Actual | Result | Label |")
    lines.append("|---|--------|----------|--------|--------|-------|")
    for idx, r in enumerate(rows):
        result = "pass" if r["ok"] else "**FAIL**"
        label = (r["label"] or "").replace("|", "\\|")
        lines.append(
            f"| {idx + 1} | {r['inputs_fmt']} | {r['expected']} | "
            f"{r['actual']} | {result} | {label} |"
        )
    lines.append("")

    failures = [r for r in rows if not r["ok"]]
    if failures:
        lines.append("## Failure detail")
        lines.append("")
        for r in failures:
            lines.append(f"### case {r['idx'] + 1}: {r['label'] or '(no label)'}")
            lines.append("")
            lines.append(f"- inputs: `{r['inputs_fmt']}`")
            lines.append(f"- expected: `{r['expected']}`")
            lines.append(f"- actual: `{r['actual']}`")
            if r["stderr"]:
                lines.append("")
                lines.append("```")
                lines.append(r["stderr"])
                lines.append("```")
            lines.append("")

    if source is not None:
        snippet, truncated = _read_source_snippet(source, max_lines=120)
        ext = source.suffix.lstrip(".")
        fence_lang = {"c": "c", "cpp": "cpp", "asm": "nasm"}.get(ext, "")
        lines.append("## Source")
        lines.append("")
        lines.append(f"```{fence_lang}")
        lines.append(snippet)
        lines.append("```")
        if truncated:
            lines.append("")
            lines.append("_(truncated; see source file for full listing)_")
        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _process_sample(
    sample: dict, ir_dir: Path, lli: Path
) -> Tuple[str, int, int, str]:
    name = sample["name"]
    cases = sample.get("semantic") or []
    source = _find_source(name)
    ir_path = ir_dir / f"{name}.ll"
    rows: List[dict] = []
    ir_stats: Dict[str, object] = {}

    if not ir_path.exists():
        for idx, case in enumerate(cases):
            rows.append(
                {
                    "idx": idx,
                    "inputs_fmt": _format_inputs(case.get("inputs", {})),
                    "expected": case["expected"],
                    "actual": "(no IR)",
                    "label": case.get("label", ""),
                    "ok": False,
                    "stderr": f"missing {ir_path}",
                }
            )
    else:
        ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
        ir_stats = _ir_summary(ir_text)
        if "@main(" not in ir_text:
            for idx, case in enumerate(cases):
                rows.append(
                    {
                        "idx": idx,
                        "inputs_fmt": _format_inputs(case.get("inputs", {})),
                        "expected": case["expected"],
                        "actual": "(no @main)",
                        "label": case.get("label", ""),
                        "ok": False,
                        "stderr": "lifted IR has no @main definition",
                    }
                )
        else:
            cleaned = cs._strip_inttoptr_stores(ir_text)
            params = cs._parse_params_from_ir(cleaned)
            fn_name = f"lifted_{name}"
            semantic_path = ir_dir / f"{name}_report.ll"
            for idx, case in enumerate(cases):
                ok, actual, stderr = _run_one_case(
                    fn_name, cleaned, params, case, semantic_path, lli
                )
                rows.append(
                    {
                        "idx": idx,
                        "inputs_fmt": _format_inputs(case.get("inputs", {})),
                        "expected": case["expected"],
                        "actual": actual,
                        "label": case.get("label", ""),
                        "ok": ok,
                        "stderr": stderr,
                    }
                )
            try:
                semantic_path.unlink()
            except OSError:
                pass

    out_path = REPORT_DIR / f"{name}.md"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _write_report(sample, source, ir_path, ir_stats, rows, out_path)

    total = len(rows)
    passed = sum(1 for r in rows if r["ok"])
    if total == 0:
        verdict = "NA"
    elif passed == total:
        verdict = "PASS"
    else:
        verdict = "FAIL"
    return name, passed, total, verdict


def _write_index(results: List[Tuple[str, int, int, str]]) -> None:
    pass_count = sum(1 for _, _, _, v in results if v == "PASS")
    fail_count = sum(1 for _, _, _, v in results if v == "FAIL")
    na_count = sum(1 for _, _, _, v in results if v == "NA")
    total = len(results)
    case_pass = sum(p for _, p, _, _ in results)
    case_total = sum(t for _, _, t, _ in results)
    lines: List[str] = []
    lines.append("# Semantic equivalence reports")
    lines.append("")
    lines.append(
        "One report per non-skipped sample under `testcases/rewrite_smoke/`. "
        "Each report compares the manifest's declared semantic cases against the "
        "lifted+optimized IR by executing the IR via LLVM `lli` and asserting the "
        "return value."
    )
    lines.append("")
    lines.append(
        f"- **Samples:** {pass_count}/{total} fully pass, "
        f"{fail_count} failing, {na_count} with no semantic cases"
    )
    lines.append(f"- **Cases:** {case_pass}/{case_total} pass overall")
    lines.append("")
    lines.append(
        "Regenerate with `python scripts/rewrite/generate_semantic_reports.py` "
        "after rerunning the lifter (`scripts\\rewrite\\run.cmd` or "
        "`python test.py quick`) so `ir_outputs/*.ll` is fresh."
    )
    lines.append("")
    lines.append("| Sample | Verdict | Cases | Report |")
    lines.append("|--------|---------|-------|--------|")
    for name, p, t, v in sorted(results):
        marker = "PASS" if v == "PASS" else f"**{v}**"
        lines.append(f"| {name} | {marker} | {p}/{t} | [{name}.md]({name}.md) |")
    lines.append("")
    (REPORT_DIR / "INDEX.md").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ir-dir", type=Path, default=DEFAULT_IR_DIR)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument(
        "--filter", nargs="*", default=[], help="sample-name substrings"
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    samples = [
        s
        for s in manifest["samples"]
        if not s.get("skip")
        and (not args.filter or any(f in s["name"] for f in args.filter))
    ]
    if not samples:
        print("no samples matched filter", file=sys.stderr)
        return 1

    lli = cs._find_lli()
    print(f"using lli: {lli}")
    print(f"ir dir:    {args.ir_dir}")
    print(f"reports:   {REPORT_DIR}")
    print(f"samples:   {len(samples)}")

    results: List[Tuple[str, int, int, str]] = []
    for i, sample in enumerate(samples, 1):
        name, passed, total, verdict = _process_sample(sample, args.ir_dir, lli)
        marker = "OK  " if verdict == "PASS" else "FAIL"
        print(f"[{i:3d}/{len(samples)}] {marker} {name}: {passed}/{total}")
        results.append((name, passed, total, verdict))

    _write_index(results)

    failed = sum(1 for _, _, _, v in results if v == "FAIL")
    print(
        f"\nWrote {len(results)} reports to {REPORT_DIR.relative_to(MERGEN).as_posix()}"
    )
    print(f"Sample verdicts: {len(results) - failed} pass, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
