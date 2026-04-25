#!/usr/bin/env python3
"""Per-sample original-vs-lifted equivalence reports.

For every non-skipped sample in ``instruction_microtests.json`` this script
produces a Markdown report at ``docs/semantic_reports/<name>_report.md`` that
compares the **native binary's** behavior against the **lifted+optimized IR**'s
behavior on the manifest-declared inputs.

Methodology per sample
----------------------
1. Generate a tiny driver in C++ that declares the target function with
   ``extern "C"`` (or, for the single C++-mangled sample ``calc_cout``, with the
   matching C++ signature) and calls it with the four Win64 integer-arg
   registers (RCX, RDX, R8, R9) supplied via ``argv``.  The driver writes the
   64-bit return value to **stderr** so that any chatter the target function
   emits to stdout (e.g. ``std::cout`` in ``calc_cout``) does not pollute the
   parsed result.
2. Build a "driver-friendly" object for the sample:
   - For ``.asm`` sources, reuse the existing ``<name>.obj`` produced by
     ``build_samples.cmd`` (NASM does not emit ``main``).
   - For ``.c``/``.cpp`` sources, recompile with ``/Dmain=__sample_main`` so the
     sample's own ``main`` does not collide with the driver's ``main``.
3. Link the driver with the sample object, producing ``<name>_eq.exe``.
4. For each declared semantic case:
     a. Run the native binary with arguments matching ``inputs``; the binary
        prints the result to stderr.
     b. Run the lifted+optimized IR via LLVM ``lli`` using a printer wrapper
        that calls ``@lifted_<name>`` and prints the i64 return value via
        ``@printf`` (stdout).
5. Compare the two values. Equivalence is "passed" iff every case returns the
   same value from both sides (and that value matches the manifest's
   ``expected`` cross-check).

Outputs
-------
- ``docs/semantic_reports/<name>_report.md`` per sample.
- ``docs/semantic_reports/INDEX.md`` rolled up across all samples.
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
from typing import Dict, List, Optional, Tuple

MERGEN = Path(__file__).resolve().parents[2]
ROOT = MERGEN.parent
SCRIPT_DIR = MERGEN / "scripts" / "rewrite"
SOURCE_DIR = MERGEN / "testcases" / "rewrite_smoke"
MANIFEST = SCRIPT_DIR / "instruction_microtests.json"
WORKDIR = ROOT / "rewrite-regression-work"
DEFAULT_IR_DIR = WORKDIR / "ir_outputs"
EQ_DIR = WORKDIR / "eq"
REPORT_DIR = MERGEN / "docs" / "semantic_reports"

sys.path.insert(0, str(SCRIPT_DIR))
import check_semantic as cs  # noqa: E402

ARG_REGS = ("RCX", "RDX", "R8", "R9")

# Hand-curated for the few samples whose target symbol is C++-mangled.  Maps
# the manifest symbol to (forward-declaration, expression returning uint64).
CXX_MANGLED_DECLS: Dict[str, Tuple[str, str]] = {
    "?calc_cout@@YAHH@Z": (
        "int calc_cout(int);",
        "static_cast<std::uint64_t>(static_cast<std::uint32_t>(calc_cout(static_cast<int>(rcx))))",
    ),
}


def _find_clang_cl() -> Path:
    for env in ("CLANG_CL_EXE", "CMAKE_C_COMPILER"):
        v = os.environ.get(env)
        if v and Path(v).exists() and "clang-cl" in Path(v).name.lower():
            return Path(v)
    hit = shutil.which("clang-cl") or shutil.which("clang-cl.exe")
    if hit:
        return Path(hit)
    for c in (Path(r"C:\Program Files\LLVM\bin\clang-cl.exe"),
              ROOT / "llvm18-install" / "bin" / "clang-cl.exe"):
        if c.exists():
            return c
    raise SystemExit("clang-cl not found; set CLANG_CL_EXE")


def _find_source(name: str) -> Optional[Path]:
    for ext in (".c", ".cpp", ".asm"):
        p = SOURCE_DIR / f"{name}{ext}"
        if p.exists():
            return p
    return None


def _driver_source(symbol: str) -> str:
    if symbol in CXX_MANGLED_DECLS:
        decl, call_expr = CXX_MANGLED_DECLS[symbol]
        body = f"    return {call_expr};"
    else:
        decl = (
            f'extern "C" std::uint64_t {symbol}(std::uint64_t, std::uint64_t, '
            f"std::uint64_t, std::uint64_t);"
        )
        body = f"    return {symbol}(rcx, rdx, r8, r9);"
    return f"""\
// Auto-generated equivalence driver for symbol `{symbol}`.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

{decl}

static std::uint64_t call_target(std::uint64_t rcx, std::uint64_t rdx,
                                 std::uint64_t r8,  std::uint64_t r9) {{
{body}
}}

static std::uint64_t parse(const char* s) {{
    if (!s) return 0;
    return static_cast<std::uint64_t>(std::strtoull(s, nullptr, 0));
}}

int main(int argc, char** argv) {{
    std::uint64_t rcx = (argc > 1) ? parse(argv[1]) : 0;
    std::uint64_t rdx = (argc > 2) ? parse(argv[2]) : 0;
    std::uint64_t r8  = (argc > 3) ? parse(argv[3]) : 0;
    std::uint64_t r9  = (argc > 4) ? parse(argv[4]) : 0;
    std::uint64_t r = call_target(rcx, rdx, r8, r9);
    std::fprintf(stderr, "%llu\\n", static_cast<unsigned long long>(r));
    return 0;
}}
"""


def _build_driver(sample: dict, source: Path, clang: Path,
                  eq_dir: Path) -> Tuple[Optional[Path], Optional[str]]:
    name = sample["name"]
    symbol = sample["symbol"]
    eq_dir.mkdir(parents=True, exist_ok=True)
    drv_cpp = eq_dir / f"{name}_driver.cpp"
    drv_cpp.write_text(_driver_source(symbol), encoding="utf-8")
    drv_obj = eq_dir / f"{name}_driver.obj"
    sample_obj = WORKDIR / f"{name}.obj"
    if not sample_obj.exists():
        return None, f"sample object missing: {sample_obj}"

    use_obj = sample_obj
    if source.suffix in (".c", ".cpp"):
        use_obj = eq_dir / f"{name}_renamed.obj"
        cflags = ["/nologo", "/Od", "/GS-", "/Dmain=__sample_main_renamed"]
        if source.suffix == ".cpp":
            cflags.append("/EHsc")
        rc = subprocess.run(
            [str(clang), *cflags, "/c", f"/Fo{use_obj}", str(source)],
            capture_output=True, text=True,
        )
        if rc.returncode != 0:
            return None, f"recompile failed: {rc.stderr.strip()[:400]}"

    rc = subprocess.run(
        [str(clang), "/nologo", "/Od", "/GS-", "/EHsc", "/c",
         f"/Fo{drv_obj}", str(drv_cpp)],
        capture_output=True, text=True,
    )
    if rc.returncode != 0:
        return None, f"driver compile failed: {rc.stderr.strip()[:400]}"

    exe = eq_dir / f"{name}_eq.exe"
    link_inputs = [str(drv_obj), str(use_obj)]
    if source.suffix == ".asm":
        link_inputs.append("kernel32.lib")
    rc = subprocess.run(
        [str(clang), "/nologo", *link_inputs, "/link",
         "/subsystem:console", f"/out:{exe}"],
        capture_output=True, text=True,
    )
    if rc.returncode != 0:
        return None, f"driver link failed: {rc.stderr.strip()[:400]}"
    return exe, None


def _run_native(exe: Path, inputs: Dict[str, int]) -> Tuple[Optional[int], str]:
    args = [str(exe)]
    for reg in ARG_REGS:
        if reg in inputs:
            args.append(str(inputs[reg]))
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return None, "native timeout"
    if r.returncode != 0:
        return None, f"native exited {r.returncode}: {(r.stdout or '').strip()[:200]}"
    err = (r.stderr or "").strip()
    last = err.splitlines()[-1] if err else ""
    try:
        return int(last), ""
    except ValueError:
        return None, f"native non-numeric stderr last line: {last!r}"


def _build_print_wrapper(fn_name: str, args_str: str) -> str:
    return (
        '\n@.eq_fmt = private unnamed_addr constant [6 x i8] c"%llu\\0A\\00", align 1\n'
        "declare i32 @printf(ptr nocapture readonly, ...)\n"
        "define i32 @semantic_print() {\n"
        "entry:\n"
        f"  %ret = call i64 @{fn_name}({args_str})\n"
        "  call i32 (ptr, ...) @printf(ptr @.eq_fmt, i64 %ret)\n"
        "  ret i32 0\n"
        "}\n"
    )


def _run_lifted(fn_name: str, cleaned_ir: str,
                params: List[Tuple[str, str]], inputs: Dict[str, int],
                semantic_path: Path, lli: Path) -> Tuple[Optional[int], str]:
    renamed = cleaned_ir.replace("@main(", f"@{fn_name}(")
    args_str = cs._build_call_args(inputs, params)
    wrapper = _build_print_wrapper(fn_name, args_str)
    semantic_path.write_text(renamed.rstrip() + "\n" + wrapper, encoding="utf-8")
    cmd = [str(lli), "--entry-function=semantic_print", str(semantic_path)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return None, "lli timeout"
    if r.returncode != 0:
        msg = (r.stderr or "").strip().splitlines()
        return None, f"lli exited {r.returncode}: {(msg[0] if msg else '')[:200]}"
    out = (r.stdout or "").strip()
    try:
        return int(out), ""
    except ValueError:
        return None, f"lli non-numeric stdout: {out!r}"


def _format_inputs(inputs: Dict[str, int]) -> str:
    if not inputs:
        return "_(none)_"
    return ", ".join(f"{k}={v}" for k, v in inputs.items())


def _read_source_snippet(path: Path, max_lines: int = 200) -> Tuple[str, bool]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    truncated = len(lines) > max_lines
    if truncated:
        lines = lines[:max_lines]
    return "\n".join(lines), truncated


_DEFINE_LINE_RE = re.compile(r"^define\s.*?@main\(.*", re.MULTILINE)


def _ir_signature(ir_text: str) -> str:
    m = _DEFINE_LINE_RE.search(ir_text)
    return m.group(0).rstrip(" {") if m else "(no @main found)"


def _equiv_value(expected: int, native: Optional[int],
                 lifted: Optional[int]) -> bool:
    if native is None or lifted is None:
        return False
    mask64 = (1 << 64) - 1
    n = native & mask64
    l = lifted & mask64
    e = expected & mask64
    if expected < (1 << 32):
        n &= 0xFFFFFFFF
        l &= 0xFFFFFFFF
    return n == l == e


def _process_sample(sample: dict, ir_dir: Path, eq_dir: Path,
                    lli: Path, clang: Path) -> Dict[str, object]:
    name = sample["name"]
    symbol = sample.get("symbol", "")
    cases = sample.get("semantic") or []
    source = _find_source(name)
    ir_path = ir_dir / f"{name}.ll"

    rows: List[Dict[str, object]] = []
    diagnostics: List[str] = []
    native_exe: Optional[Path] = None

    if source is None:
        diagnostics.append("source not found in testcases/rewrite_smoke")
    else:
        native_exe, err = _build_driver(sample, source, clang, eq_dir)
        if err:
            diagnostics.append(f"driver build skipped: {err}")
            native_exe = None

    cleaned_ir: Optional[str] = None
    params: List[Tuple[str, str]] = []
    ir_signature = ""
    if not ir_path.exists():
        diagnostics.append(f"lifted IR missing: {ir_path}")
    else:
        ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
        ir_signature = _ir_signature(ir_text)
        if "@main(" not in ir_text:
            diagnostics.append("lifted IR has no @main definition")
        else:
            cleaned_ir = cs._strip_inttoptr_stores(ir_text)
            params = cs._parse_params_from_ir(cleaned_ir)

    semantic_path = ir_dir / f"{name}_eq.ll"
    fn_name = f"lifted_{name}"

    for idx, case in enumerate(cases):
        inputs = case.get("inputs", {})
        expected = case["expected"]
        native_val: Optional[int] = None
        native_err = ""
        if native_exe is not None:
            native_val, native_err = _run_native(native_exe, inputs)
        lifted_val: Optional[int] = None
        lifted_err = ""
        if cleaned_ir is not None:
            lifted_val, lifted_err = _run_lifted(
                fn_name, cleaned_ir, params, inputs, semantic_path, lli
            )
        equiv = _equiv_value(expected, native_val, lifted_val)
        rows.append({
            "idx": idx,
            "inputs_fmt": _format_inputs(inputs),
            "expected": expected,
            "native": native_val,
            "native_err": native_err,
            "lifted": lifted_val,
            "lifted_err": lifted_err,
            "equiv": equiv,
            "label": case.get("label", ""),
        })
    try:
        semantic_path.unlink()
    except OSError:
        pass

    total = len(rows)
    passed = sum(1 for r in rows if r["equiv"])
    if total == 0:
        verdict = "NA (no semantic cases declared)" if not cases else "FAIL"
    elif passed == total:
        verdict = "PASS"
    else:
        verdict = f"FAIL ({total - passed}/{total})"

    return {
        "name": name, "symbol": symbol, "source": source, "ir_path": ir_path,
        "ir_signature": ir_signature, "rows": rows, "verdict": verdict,
        "passed": passed, "total": total, "diagnostics": diagnostics,
        "native_exe": native_exe,
    }


def _fmt_int(v: Optional[int]) -> str:
    return "—" if v is None else str(v)


def _write_report(result: Dict[str, object]) -> None:
    name = result["name"]
    out_path = REPORT_DIR / f"{name}_report.md"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append(f"# {name} - original vs lifted equivalence")
    lines.append("")
    lines.append(f"- **Verdict:** {result['verdict']}")
    lines.append(f"- **Cases:** {result['passed']}/{result['total']} equivalent")
    src = result["source"]
    if src is not None:
        lines.append(f"- **Source:** `{src.relative_to(MERGEN).as_posix()}`")
    else:
        lines.append("- **Source:** _(not found)_")
    ir_path: Path = result["ir_path"]  # type: ignore[assignment]
    if ir_path.exists():
        lines.append(f"- **Lifted IR:** `{ir_path.relative_to(ROOT).as_posix()}`")
    else:
        lines.append("- **Lifted IR:** _(missing)_")
    lines.append(f"- **Symbol:** `{result['symbol']}`")
    if result["native_exe"] is not None:
        rel = Path(result["native_exe"]).relative_to(ROOT).as_posix()  # type: ignore[arg-type]
        lines.append(f"- **Native driver:** `{rel}`")
    else:
        lines.append("- **Native driver:** _(not built)_")
    if result["ir_signature"]:
        lines.append(f"- **Lifted signature:** `{result['ir_signature']}`")
    if result["diagnostics"]:
        lines.append("")
        lines.append("**Diagnostics:**")
        for d in result["diagnostics"]:
            lines.append(f"- {d}")
    lines.append("")
    lines.append("## Equivalence (native vs lifted)")
    lines.append("")
    lines.append(
        "Each row runs the same inputs through (a) the original program "
        "compiled to a real Win64 binary that calls "
        f"`{result['symbol']}` directly, and (b) the lifted+optimized LLVM IR "
        "executed via `lli`. A case is equivalent only if both observations "
        "agree and also match the manifest's expected value."
    )
    lines.append("")
    lines.append("| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |")
    lines.append("|---|--------|----------|--------|--------|------------|-------|")
    for r in result["rows"]:
        eq = "yes" if r["equiv"] else "**no**"
        label = (r["label"] or "").replace("|", "\\|")
        native = _fmt_int(r["native"])
        if r["native"] is None and r["native_err"]:
            native = f"_err: {r['native_err']}_"
        lifted = _fmt_int(r["lifted"])
        if r["lifted"] is None and r["lifted_err"]:
            lifted = f"_err: {r['lifted_err']}_"
        lines.append(
            f"| {r['idx'] + 1} | {r['inputs_fmt']} | {r['expected']} | "
            f"{native} | {lifted} | {eq} | {label} |"
        )
    lines.append("")

    failures = [r for r in result["rows"] if not r["equiv"]]
    if failures:
        lines.append("## Failure detail")
        lines.append("")
        for r in failures:
            lines.append(f"### case {r['idx'] + 1}: {r['label'] or '(no label)'}")
            lines.append("")
            lines.append(f"- inputs: `{r['inputs_fmt']}`")
            lines.append(f"- manifest expected: `{r['expected']}`")
            lines.append(f"- native: `{_fmt_int(r['native'])}`")
            if r["native_err"]:
                lines.append(f"- native error: `{r['native_err']}`")
            lines.append(f"- lifted: `{_fmt_int(r['lifted'])}`")
            if r["lifted_err"]:
                lines.append(f"- lifted error: `{r['lifted_err']}`")
            lines.append("")

    if src is not None:
        snippet, truncated = _read_source_snippet(src, max_lines=200)
        ext = src.suffix.lstrip(".")
        fence = {"c": "c", "cpp": "cpp", "asm": "nasm"}.get(ext, "")
        lines.append("## Source")
        lines.append("")
        lines.append(f"```{fence}")
        lines.append(snippet)
        lines.append("```")
        if truncated:
            lines.append("")
            lines.append("_(truncated; see source file for the full listing)_")
        lines.append("")
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _write_index(results: List[Dict[str, object]]) -> None:
    pass_count = sum(1 for r in results if r["verdict"] == "PASS")
    fail_count = sum(1 for r in results if str(r["verdict"]).startswith("FAIL"))
    na_count = sum(1 for r in results if str(r["verdict"]).startswith("NA"))
    total = len(results)
    case_pass = sum(int(r["passed"]) for r in results)  # type: ignore[arg-type]
    case_total = sum(int(r["total"]) for r in results)  # type: ignore[arg-type]

    lines: List[str] = [
        "# Equivalence reports (original vs lifted)",
        "",
        "Each report compares the **native binary** built from "
        "`testcases/rewrite_smoke/<name>` (linked through a small driver that "
        "calls the target symbol directly) against the **lifted+optimized "
        "LLVM IR** in `rewrite-regression-work/ir_outputs/<name>.ll` (executed "
        "via LLVM `lli`) on the manifest-declared input cases.",
        "",
        f"- **Samples:** {pass_count}/{total} equivalent across all cases, "
        f"{fail_count} failing, {na_count} with no semantic cases",
        f"- **Cases:** {case_pass}/{case_total} equivalent overall",
        "",
        "Regenerate after a re-lift:",
        "",
        "```",
        "set CLANG_CL_EXE=C:\\Program Files\\LLVM\\bin\\clang-cl.exe",
        "scripts\\rewrite\\run.cmd",
        "python scripts\\rewrite\\generate_equivalence_reports.py",
        "```",
        "",
        "| Sample | Verdict | Cases | Report |",
        "|--------|---------|-------|--------|",
    ]
    for r in sorted(results, key=lambda x: str(x["name"])):
        v = str(r["verdict"])
        marker = "PASS" if v == "PASS" else f"**{v}**"
        lines.append(
            f"| {r['name']} | {marker} | {r['passed']}/{r['total']} | "
            f"[{r['name']}_report.md]({r['name']}_report.md) |"
        )
    lines.append("")
    (REPORT_DIR / "INDEX.md").write_text("\n".join(lines).rstrip() + "\n",
                                         encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ir-dir", type=Path, default=DEFAULT_IR_DIR)
    ap.add_argument("--manifest", type=Path, default=MANIFEST)
    ap.add_argument("--filter", nargs="*", default=[])
    ap.add_argument("--keep-eq-dir", action="store_true")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    samples = [
        s for s in manifest["samples"]
        if not s.get("skip")
        and (not args.filter or any(f in s["name"] for f in args.filter))
    ]
    if not samples:
        print("no samples matched filter", file=sys.stderr)
        return 1

    lli = cs._find_lli()
    clang = _find_clang_cl()
    EQ_DIR.mkdir(parents=True, exist_ok=True)
    print(f"clang-cl: {clang}")
    print(f"lli:      {lli}")
    print(f"ir_dir:   {args.ir_dir}")
    print(f"eq_dir:   {EQ_DIR}")
    print(f"reports:  {REPORT_DIR}")
    print(f"samples:  {len(samples)}")

    results: List[Dict[str, object]] = []
    for i, sample in enumerate(samples, 1):
        try:
            res = _process_sample(sample, args.ir_dir, EQ_DIR, lli, clang)
        except Exception as exc:
            res = {
                "name": sample["name"], "symbol": sample.get("symbol", ""),
                "source": _find_source(sample["name"]),
                "ir_path": args.ir_dir / f"{sample['name']}.ll",
                "ir_signature": "", "rows": [],
                "verdict": f"FAIL (exception: {exc})", "passed": 0,
                "total": len(sample.get("semantic") or []),
                "diagnostics": [f"exception: {exc}"], "native_exe": None,
            }
        _write_report(res)
        v = str(res["verdict"])
        marker = "OK  " if v == "PASS" else ("NA  " if v.startswith("NA") else "FAIL")
        print(f"[{i:3d}/{len(samples)}] {marker} {res['name']}: {res['passed']}/{res['total']}")
        results.append(res)

    _write_index(results)
    if not args.keep_eq_dir:
        shutil.rmtree(EQ_DIR, ignore_errors=True)
    failed = sum(1 for r in results if str(r["verdict"]).startswith("FAIL"))
    print(f"\nWrote {len(results)} reports to "
          f"{REPORT_DIR.relative_to(MERGEN).as_posix()}")
    print(f"Sample verdicts: {len(results) - failed} non-fail, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
