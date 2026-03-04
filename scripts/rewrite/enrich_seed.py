#!/usr/bin/env python3
"""Enrich oracle seed: add expected register/flag fields to auto-discovered cases.

For each case with oracle=none and empty expected fields, this script:
1. Disassembles the instruction with Capstone to understand its semantics
2. Sets oracle=unicorn
3. Populates expected.registers with affected registers from the initial set
4. Populates expected.flags with relevant arithmetic flags

The oracle generator then fills in the actual numeric expected values via Unicorn.
"""
import argparse
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    import capstone.x86_const as x86c
except ImportError:
    raise SystemExit("capstone is required: pip install capstone")


# Map from Capstone x86 register IDs to our test register names
_CS_REG_TO_NAME: Dict[int, str] = {
    x86c.X86_REG_RAX: "RAX", x86c.X86_REG_EAX: "RAX", x86c.X86_REG_AX: "RAX",
    x86c.X86_REG_AL: "RAX", x86c.X86_REG_AH: "RAX",
    x86c.X86_REG_RBX: "RBX", x86c.X86_REG_EBX: "RBX", x86c.X86_REG_BX: "RBX",
    x86c.X86_REG_BL: "RBX", x86c.X86_REG_BH: "RBX",
    x86c.X86_REG_RCX: "RCX", x86c.X86_REG_ECX: "RCX", x86c.X86_REG_CX: "RCX",
    x86c.X86_REG_CL: "RCX", x86c.X86_REG_CH: "RCX",
    x86c.X86_REG_RDX: "RDX", x86c.X86_REG_EDX: "RDX", x86c.X86_REG_DX: "RDX",
    x86c.X86_REG_DL: "RDX", x86c.X86_REG_DH: "RDX",
    x86c.X86_REG_RSI: "RSI", x86c.X86_REG_ESI: "RSI", x86c.X86_REG_SI: "RSI",
    x86c.X86_REG_RDI: "RDI", x86c.X86_REG_EDI: "RDI", x86c.X86_REG_DI: "RDI",
    x86c.X86_REG_R8: "R8", x86c.X86_REG_R8D: "R8", x86c.X86_REG_R8W: "R8", x86c.X86_REG_R8B: "R8",
    x86c.X86_REG_R9: "R9", x86c.X86_REG_R9D: "R9", x86c.X86_REG_R9W: "R9", x86c.X86_REG_R9B: "R9",
    x86c.X86_REG_R10: "R10", x86c.X86_REG_R10D: "R10", x86c.X86_REG_R10W: "R10", x86c.X86_REG_R10B: "R10",
    x86c.X86_REG_R11: "R11", x86c.X86_REG_R11D: "R11", x86c.X86_REG_R11W: "R11", x86c.X86_REG_R11B: "R11",
    x86c.X86_REG_R12: "R12", x86c.X86_REG_R12D: "R12", x86c.X86_REG_R12W: "R12", x86c.X86_REG_R12B: "R12",
    x86c.X86_REG_R13: "R13", x86c.X86_REG_R13D: "R13", x86c.X86_REG_R13W: "R13", x86c.X86_REG_R13B: "R13",
    x86c.X86_REG_R14: "R14", x86c.X86_REG_R14D: "R14", x86c.X86_REG_R14W: "R14", x86c.X86_REG_R14B: "R14",
    x86c.X86_REG_R15: "R15", x86c.X86_REG_R15D: "R15", x86c.X86_REG_R15W: "R15", x86c.X86_REG_R15B: "R15",
    x86c.X86_REG_EFLAGS: "RFLAGS",
}

# The registers we have in our initial state
INITIAL_REGS = {"RAX", "RBX", "RCX", "RDX"}

# Standard arithmetic flags
ARITH_FLAGS = ["FLAG_CF", "FLAG_OF", "FLAG_ZF", "FLAG_SF", "FLAG_PF", "FLAG_AF"]
# Flags for logical operations (AF is undefined, CF/OF are cleared)
LOGIC_FLAGS = ["FLAG_CF", "FLAG_OF", "FLAG_ZF", "FLAG_SF", "FLAG_PF"]

# Handlers that are control flow and should NOT get oracle checks (they change RIP/RSP)
CONTROL_FLOW_HANDLERS = {
    "call", "ret", "jmp",
    "jnz", "jz", "js", "jns", "jle", "jl", "jnl", "jnle",
    "jbe", "jb", "jnb", "jnbe", "jo", "jno", "jp", "jnp",
    "leave",
}

# Handlers that modify RSP and are tricky to test in isolation
STACK_HANDLERS = {"push", "pop", "pushfq", "popfq"}

# Handlers that are system instructions (rdtsc, cpuid) with non-deterministic results
NONDETERMINISTIC_HANDLERS = {"rdtsc", "cpuid"}

# Handlers that modify memory strings (need memory setup)
MEMORY_HANDLERS = {"movs_X", "stosx"}

# Handlers that should be skipped entirely
SKIP_HANDLERS = CONTROL_FLOW_HANDLERS | STACK_HANDLERS | NONDETERMINISTIC_HANDLERS | MEMORY_HANDLERS

# Flag-only handlers (no register output, just flags)
FLAG_ONLY_HANDLERS = {"cmp", "test", "bt", "btr", "bts", "btc"}

# Sign/zero extension handlers (result depends on register size, check RAX)
EXTENSION_HANDLERS = {"cbw", "cwde", "cdqe", "cwd", "cdq", "cqo"}

# Handlers that modify both RAX and RDX (multiply/divide)
RAX_RDX_HANDLERS = {"imul2", "mul2", "div2", "idiv2"}

# Flag manipulation handlers
FLAG_MANIP_HANDLERS = {
    "stc": ["FLAG_CF"],
    "clc": ["FLAG_CF"],
    "cmc": ["FLAG_CF"],
    "std": ["FLAG_DF"],
    "cld": ["FLAG_DF"],
    "cli": [],  # IF flag, not testable
}

# Handlers where checking flags is problematic (flags are fully defined by the instruction)
NO_FLAG_HANDLERS = {
    "mov", "lea", "cmovcc", "bswap", "xchg", "cmpxchg",
    "lahf", "sahf",
}


def get_written_regs(instruction_bytes: List[int]) -> Tuple[Set[str], bool]:
    """Disassemble and return written GPR names + whether EFLAGS is written."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    code = bytes(instruction_bytes)

    written_regs: Set[str] = set()
    writes_flags = False

    for insn in md.disasm(code, 0x1000000):
        _, regs_write = insn.regs_access()
        for reg_id in regs_write:
            name = _CS_REG_TO_NAME.get(reg_id)
            if name == "RFLAGS":
                writes_flags = True
            elif name is not None:
                written_regs.add(name)
        break  # Only first instruction

    return written_regs, writes_flags


def enrich_case(case: dict) -> dict:
    """Add expected fields to an auto-discovered case."""
    handler = case.get("handler", "").lower()

    # Skip cases that are already enriched
    if case.get("oracle") != "none":
        return case
    expected = case.get("expected", {})
    if expected.get("registers") or expected.get("flags"):
        return case

    # Skip control flow and other problematic handlers
    if handler in SKIP_HANDLERS:
        case["skip"] = True
        case["skip_reason"] = f"handler '{handler}' requires special test setup"
        return case

    instruction_bytes = case.get("instruction_bytes", [])
    if not instruction_bytes:
        return case

    # Determine which registers to check
    written_regs, writes_flags = get_written_regs(instruction_bytes)

    # Intersect with registers we have initial values for
    check_regs = written_regs & INITIAL_REGS

    # Special cases
    if handler in RAX_RDX_HANDLERS:
        check_regs = {"RAX", "RDX"}
    elif handler in EXTENSION_HANDLERS:
        check_regs = {"RAX"}
        if handler in ("cwd", "cdq", "cqo"):
            check_regs.add("RDX")

    # If no registers detected, try RAX as fallback for most handlers
    if not check_regs and handler not in FLAG_MANIP_HANDLERS and handler not in FLAG_ONLY_HANDLERS:
        check_regs = {"RAX"}

    # Determine which flags to check
    check_flags: List[str] = []
    if handler in FLAG_MANIP_HANDLERS:
        check_flags = FLAG_MANIP_HANDLERS[handler]
        check_regs = set()  # Flag-only
    elif handler in NO_FLAG_HANDLERS:
        check_flags = []
    elif handler in FLAG_ONLY_HANDLERS:
        check_flags = ARITH_FLAGS
    elif writes_flags:
        check_flags = ARITH_FLAGS

    # Build enriched expected
    case["oracle"] = "unicorn"
    case["expected"] = {
        "registers": {reg: "0x0" for reg in sorted(check_regs)},
        "flags": {flag: 0 for flag in check_flags},
    }

    return case


def main():
    parser = argparse.ArgumentParser(description="Enrich oracle seed with expected fields")
    parser.add_argument(
        "--seed",
        default="scripts/rewrite/oracle_seed_full_handlers.json",
        help="Input seed JSON",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output enriched seed JSON (default: overwrite input)",
    )
    args = parser.parse_args()

    seed_path = Path(args.seed)
    out_path = Path(args.out) if args.out else seed_path

    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])

    enriched = 0
    skipped = 0
    for i, case in enumerate(cases):
        before_oracle = case.get("oracle")
        cases[i] = enrich_case(case)
        if cases[i].get("oracle") != before_oracle:
            enriched += 1
        if cases[i].get("skip"):
            skipped += 1

    payload["cases"] = cases
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"Enriched: {enriched} cases, Skipped: {skipped} cases")
    print(f"Total: {len(cases)} cases")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
