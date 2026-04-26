#!/usr/bin/env python3
"""Generate predicate-gated reducer VM samples for the rewrite_smoke corpus.

Covers the family:
    vm_<width>_<op>_<pred>_thresh64_loop

where:
    width ∈ {byte, word, dword}                       (8, 16, 32 bit lane)
    op    ∈ {and, or, xor, sum}                       (reducer)
    pred  ∈ {uge, ult}                                (gate vs threshold)

These are the templates that dominate the recent corpus expansion. The
generator emits both the C source (matching the in-tree style exactly) and the
matching `instruction_microtests.json` manifest entry, with semantic expected
values computed in Python so the manifest is self-checking.

Usage:

    # Verify the generator's algorithm matches an existing in-tree sample
    # (re-derives the manifest entry and asserts every `expected` matches):
    python generate_vm_sample.py --check vm_byte_and_uge_thresh64_loop

    # Emit a new sample to stdout (source + manifest snippet):
    python generate_vm_sample.py --emit vm_word_or_ult_thresh64_loop

    # Emit a new sample to disk:
    python generate_vm_sample.py --emit vm_word_or_ult_thresh64_loop \\
        --out-dir testcases/rewrite_smoke

The generator does NOT modify the manifest. After --emit, the printed JSON
snippet must be inserted into scripts/rewrite/instruction_microtests.json by
hand (or by tooling). This keeps the manifest as the single source of truth
and avoids accidental schema drift.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "scripts" / "rewrite" / "instruction_microtests.json"
SMOKE_DIR = REPO_ROOT / "testcases" / "rewrite_smoke"

WIDTHS = {
    # name → (bits, mask, threshold (mid-point), n_mask, prefix, enum_prefix, identity_for_and)
    "byte":  ( 8, 0xFF,       0x80,       7, "b", "B", 0xFF),
    "word":  (16, 0xFFFF,     0x8000,     3, "w", "W", 0xFFFF),
    "dword": (32, 0xFFFFFFFF, 0x80000000, 1, "d", "D", 0xFFFFFFFF),
}

OPS = ("and", "or", "xor", "sum")
PREDS = ("uge", "ult")

# The seven canonical inputs every reducer sample must cover. Picked so each
# input exercises a different lane shape (zero, single-lane, all-set, mixed
# nibbles, all-high). Extend per family if a sample needs more.
CANONICAL_INPUTS = [
    (0,                       "x=0 baseline"),
    (1,                       "x=1 minimal n"),
    (0xCAFEBABE,              "0xCAFEBABE mixed lanes"),
    (0xDEADBEEF,              "0xDEADBEEF mixed lanes"),
    (0xFFFFFFFFFFFFFFFF,      "all-ones"),
    (0x80808080_80808080,     "0x8080... high-bit lanes"),
    (0x8000_8000_8000_FFFF,   "0x800080008000FFFF mixed"),
]

# Manifest pattern fragment per op. These are the LLVM IR lexemes the rewrite
# gate already greps for in the existing samples — kept identical so generated
# entries pass the same verifier.
OP_PATTERNS = {
    "and": ["icmp", "and"],
    "or":  ["icmp", "or"],
    "xor": ["icmp", "xor"],
    "sum": ["icmp", "add"],
}


def parse_name(name: str) -> tuple[str, str, str]:
    """Parse vm_<width>_<op>_<pred>_thresh64_loop into (width, op, pred)."""
    m = re.fullmatch(
        r"vm_(?P<width>byte|word|dword)_(?P<op>and|or|xor|sum)_(?P<pred>uge|ult)_thresh64_loop",
        name,
    )
    if not m:
        raise ValueError(
            f"name {name!r} does not match vm_<width>_<op>_<pred>_thresh64_loop"
        )
    return m["width"], m["op"], m["pred"]


def reduce_value(width: str, op: str, pred: str, x: int) -> int:
    """Mirror the C reference exactly, returning the uint64 the lift target returns."""
    bits, mask, threshold, n_mask, *_rest = WIDTHS[width]
    n = ((x & n_mask) + 1) & 0xFFFFFFFFFFFFFFFF
    s = x & 0xFFFFFFFFFFFFFFFF
    if op == "and":
        acc = mask
    else:  # or, xor, sum
        acc = 0

    while n > 0:
        lane = s & mask
        if pred == "uge":
            qualifies = lane >= threshold
        else:
            qualifies = lane < threshold

        # AND uses the mask as the false-branch identity; the others use 0.
        false_id = mask if op == "and" else 0
        gated = lane if qualifies else false_id

        if op == "and":
            acc = acc & gated
        elif op == "or":
            acc = acc | gated
        elif op == "xor":
            acc = acc ^ gated
        else:  # sum
            acc = (acc + gated) & 0xFFFFFFFFFFFFFFFF

        s = (s >> bits) & 0xFFFFFFFFFFFFFFFF
        n -= 1

    return acc & 0xFFFFFFFFFFFFFFFF


def render_source(name: str) -> str:
    width, op, pred = parse_name(name)
    bits, mask, threshold, n_mask, prefix, enum_prefix, _ = WIDTHS[width]
    op_caps = op.upper()
    enum_root = f"{enum_prefix}{op_caps}"
    target = f"{name}_target"

    # Lane-temp variable letter mirrors the in-tree convention: byte→b, word→w, dword→d.
    lane_var = prefix

    if op == "and":
        identity = mask
        acc_init = f"0x{mask:X}ull"
        accum_line = f"acc = acc & (({lane_var} {'>=' if pred == 'uge' else '<'} 0x{threshold:X}ull) ? {lane_var} : 0x{identity:X}ull);"
        identity_doc = f"identity 0x{identity:X}"
    else:
        identity = 0
        acc_init = "0"
        gated_true = lane_var
        if op == "or":
            accum_line = f"acc = acc | (({lane_var} {'>=' if pred == 'uge' else '<'} 0x{threshold:X}ull) ? {gated_true} : 0ull);"
        elif op == "xor":
            accum_line = f"acc = acc ^ (({lane_var} {'>=' if pred == 'uge' else '<'} 0x{threshold:X}ull) ? {gated_true} : 0ull);"
        else:  # sum
            accum_line = f"acc = acc + (({lane_var} {'>=' if pred == 'uge' else '<'} 0x{threshold:X}ull) ? {gated_true} : 0ull);"
        identity_doc = "identity 0"

    pred_word = "above" if pred == "uge" else "below"

    lines = [
        f"/* PC-state VM that {op_caps}-accumulates {width}s {pred_word} 0x{threshold:X} ({identity_doc}):",
        " *",
        f" *   n = (x & {n_mask}) + 1;",
        f" *   s = x; acc = 0x{identity:X};",
        " *   while (n) {",
        f" *     uint64_t {lane_var} = s & 0x{mask:X};",
        f" *     {accum_line.replace('acc =', 'acc =').replace('acc ', 'acc ', 1)}",
        f" *     s >>= {bits};",
        " *     n--;",
        " *   }",
        " *   return acc;",
        " *",
        f" * Lift target: {target}.",
        " *",
        f" * Generated by scripts/rewrite/generate_vm_sample.py for the predicate-gated",
        f" * reducer family ({width} stride, {op}, {pred}).",
        " */",
        "#include <stdio.h>",
        "#include <stdint.h>",
        "",
        f"enum {enum_prefix}{op_caps}VmPc {{",
        f"    {enum_root}_INIT_ALL = 0,",
        f"    {enum_root}_CHECK    = 1,",
        f"    {enum_root}_BODY     = 2,",
        f"    {enum_root}_HALT     = 3,",
        "};",
        "",
        "__declspec(noinline)",
        f"uint64_t {target}(uint64_t x) {{",
        "    uint64_t n   = 0;",
        "    uint64_t s   = 0;",
        "    uint64_t acc = 0;",
        f"    int      pc  = {enum_root}_INIT_ALL;",
        "",
        "    while (1) {",
        f"        if (pc == {enum_root}_INIT_ALL) {{",
        f"            n = (x & {n_mask}ull) + 1ull;",
        "            s = x;",
        f"            acc = {acc_init};",
        f"            pc = {enum_root}_CHECK;",
        f"        }} else if (pc == {enum_root}_CHECK) {{",
        f"            pc = (n > 0ull) ? {enum_root}_BODY : {enum_root}_HALT;",
        f"        }} else if (pc == {enum_root}_BODY) {{",
        f"            uint64_t {lane_var} = s & 0x{mask:X}ull;",
        f"            {accum_line}",
        f"            s = s >> {bits};",
        "            n = n - 1ull;",
        f"            pc = {enum_root}_CHECK;",
        f"        }} else if (pc == {enum_root}_HALT) {{",
        "            return acc;",
        "        } else {",
        "            return 0xFFFFFFFFFFFFFFFFull;",
        "        }",
        "    }",
        "}",
        "",
        "int main(void) {",
        f'    printf("{name}(0xCAFEBABE)=%llu\\n",',
        f"           (unsigned long long){target}(0xCAFEBABEull));",
        "    return 0;",
        "}",
        "",
    ]
    return "\n".join(lines)


def build_manifest_entry(name: str, inputs: Iterable[tuple[int, str]] | None = None) -> dict:
    width, op, pred = parse_name(name)
    chosen = list(inputs) if inputs is not None else CANONICAL_INPUTS
    semantic = []
    for x, label in chosen:
        expected = reduce_value(width, op, pred, x)
        semantic.append({"inputs": {"RCX": x}, "expected": expected, "label": label})
    return {
        "name": name,
        "symbol": f"{name}_target",
        "patterns": OP_PATTERNS[op],
        "semantic": semantic,
    }


def cmd_check(name: str) -> int:
    """Re-derive expected values for an existing manifest sample and assert equality."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = manifest["samples"] if isinstance(manifest, dict) and "samples" in manifest else manifest
    entry = next((s for s in samples if s.get("name") == name), None)
    if entry is None:
        print(f"check: sample {name!r} not in manifest", file=sys.stderr)
        return 1

    width, op, pred = parse_name(name)
    failures = []
    for case in entry.get("semantic", []):
        x = case["inputs"]["RCX"]
        want = case["expected"]
        got = reduce_value(width, op, pred, x)
        if got != want:
            failures.append(
                f"  RCX=0x{x:X}: manifest expected {want}, generator computed {got}"
                f" ({case.get('label', '')})"
            )

    if failures:
        print(f"check: {name}: {len(failures)} mismatch(es):", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        return 1
    print(f"check: {name}: {len(entry.get('semantic', []))} case(s) match generator")
    return 0


def cmd_emit(name: str, out_dir: Path | None) -> int:
    parse_name(name)  # validates
    source = render_source(name)
    entry = build_manifest_entry(name)
    snippet = json.dumps(entry, indent=6, ensure_ascii=False)

    if out_dir is None:
        print("=== source ===")
        print(source)
        print("=== manifest entry (insert into scripts/rewrite/instruction_microtests.json) ===")
        print(snippet)
        return 0

    out_dir = out_dir.resolve()
    if not out_dir.is_dir():
        print(f"emit: out-dir not found: {out_dir}", file=sys.stderr)
        return 1
    src_path = out_dir / f"{name}.c"
    if src_path.exists():
        print(f"emit: refusing to overwrite {src_path}", file=sys.stderr)
        return 1
    src_path.write_text(source, encoding="utf-8")
    print(f"emit: wrote {src_path}")
    print("=== manifest entry (insert into scripts/rewrite/instruction_microtests.json) ===")
    print(snippet)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    chk = sub.add_parser("check", help="re-derive an existing manifest sample's semantics")
    chk.add_argument("name")

    em = sub.add_parser("emit", help="emit source + manifest snippet for a new sample")
    em.add_argument("name")
    em.add_argument("--out-dir", type=Path, default=None,
                    help="write .c into this directory (default: stdout only)")

    # Backwards-compat: accept --check / --emit flags.
    parser.add_argument("--check", dest="legacy_check", default=None)
    parser.add_argument("--emit",  dest="legacy_emit",  default=None)
    parser.add_argument("--out-dir", dest="legacy_out_dir", type=Path, default=None)

    args = parser.parse_args(argv[1:])

    if args.cmd == "check":
        return cmd_check(args.name)
    if args.cmd == "emit":
        return cmd_emit(args.name, args.out_dir)
    if args.legacy_check is not None:
        return cmd_check(args.legacy_check)
    if args.legacy_emit is not None:
        return cmd_emit(args.legacy_emit, args.legacy_out_dir)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
