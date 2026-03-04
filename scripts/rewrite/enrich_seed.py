#!/usr/bin/env python3
"""Enrich oracle seed: add expected register/flag fields to auto-discovered cases.

For each case with oracle=none and empty expected fields, this script:
1. Disassembles the instruction with Capstone to understand its semantics
2. Detects memory operands and uninitialized register reads
3. Sets oracle=unicorn (or skip if not emulatable)
4. Populates expected.registers with affected registers from the initial set
5. Populates expected.flags with relevant arithmetic flags

The oracle generator then fills in the actual numeric expected values via Unicorn.
"""
import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
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
    x86c.X86_REG_RBP: "RBP", x86c.X86_REG_EBP: "RBP", x86c.X86_REG_BP: "RBP",
    x86c.X86_REG_RSP: "RSP", x86c.X86_REG_ESP: "RSP", x86c.X86_REG_SP: "RSP",
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

# Standard arithmetic flags
ARITH_FLAGS = ["FLAG_CF", "FLAG_OF", "FLAG_ZF", "FLAG_SF", "FLAG_PF", "FLAG_AF"]
LOGIC_FLAGS = ["FLAG_CF", "FLAG_OF", "FLAG_ZF", "FLAG_SF", "FLAG_PF"]

# Handlers that are control flow (change RIP/RSP fundamentally)
CONTROL_FLOW_HANDLERS = {
    "call", "ret", "jmp",
    "jnz", "jz", "js", "jns", "jle", "jl", "jnl", "jnle",
    "jbe", "jb", "jnb", "jnbe", "jo", "jno", "jp", "jnp",
    "leave",
}

# Stack-modifying handlers
STACK_HANDLERS = {"push", "pop", "pushfq", "popfq"}

# Non-deterministic system instructions
NONDETERMINISTIC_HANDLERS = {"rdtsc", "cpuid"}

# Memory string instructions (need RSI/RDI memory setup)
MEMORY_HANDLERS = {"movs_X", "movs_x", "stosx"}

# All handlers to skip unconditionally
SKIP_HANDLERS = CONTROL_FLOW_HANDLERS | STACK_HANDLERS | NONDETERMINISTIC_HANDLERS | MEMORY_HANDLERS

# Flag-only handlers (no register output, just flags)
FLAG_ONLY_HANDLERS = {"cmp", "test", "bt", "btr", "bts", "btc"}

# Sign/zero extension handlers
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
    "cli": [],
}

# Handlers where flag checking is not meaningful
NO_FLAG_HANDLERS = {
    "mov", "lea", "cmovcc", "bswap", "xchg", "cmpxchg",
    "lahf", "sahf",
}


@dataclass
class InsnAnalysis:
    """Analysis result from disassembling instruction bytes."""
    read_regs: Set[str]
    written_regs: Set[str]
    writes_flags: bool
    has_memory_operand: bool
    disasm_text: str


def _get_initial_regs_from_case(case: dict) -> Set[str]:
    """Return the set of register names initialized in this case."""
    initial = case.get("initial", {})
    regs = initial.get("registers", {})
    return {name.upper() for name in regs.keys()}


def analyze_instruction(instruction_bytes: List[int]) -> Optional[InsnAnalysis]:
    """Disassemble and analyze the instruction."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    code = bytes(instruction_bytes)

    read_regs: Set[str] = set()
    written_regs: Set[str] = set()
    writes_flags = False
    has_memory = False

    for insn in md.disasm(code, 0x1000000):
        # Check for memory operands
        for op in insn.operands:
            if op.type == CS_OP_MEM:
                has_memory = True

        regs_read, regs_write = insn.regs_access()
        for reg_id in regs_read:
            name = _CS_REG_TO_NAME.get(reg_id)
            if name and name != "RFLAGS":
                read_regs.add(name)
        for reg_id in regs_write:
            name = _CS_REG_TO_NAME.get(reg_id)
            if name == "RFLAGS":
                writes_flags = True
            elif name is not None:
                written_regs.add(name)

        return InsnAnalysis(
            read_regs=read_regs,
            written_regs=written_regs,
            writes_flags=writes_flags,
            has_memory_operand=has_memory,
            disasm_text=f"{insn.mnemonic} {insn.op_str}",
        )

    return None


def enrich_case(case: dict) -> dict:
    """Add expected fields to an auto-discovered case."""
    handler = case.get("handler", "").lower()

    # Skip cases that are already enriched or have oracle != none
    oracle = str(case.get("oracle", "")).strip().lower()
    if oracle and oracle != "none":
        return case
    expected = case.get("expected", {})
    if expected.get("registers") or expected.get("flags"):
        return case

    # Skip control flow and other problematic handlers by name
    if handler in SKIP_HANDLERS:
        case["skip"] = True
        case["skip_reason"] = f"handler '{handler}' requires special test setup"
        return case

    instruction_bytes = case.get("instruction_bytes", [])
    if not instruction_bytes:
        return case

    # Analyze the instruction
    analysis = analyze_instruction(instruction_bytes)
    if analysis is None:
        case["skip"] = True
        case["skip_reason"] = "failed to disassemble instruction bytes"
        return case

    # Skip instructions with memory operands (Unicorn needs mapped memory)
    if analysis.has_memory_operand:
        case["skip"] = True
        case["skip_reason"] = f"memory operand in '{analysis.disasm_text}'; needs mapped memory for emulation"
        return case

    # Check for uninitialized register reads
    initialized_regs = _get_initial_regs_from_case(case)
    # RIP and RSP are always implicitly initialized by the emulator
    initialized_regs |= {"RIP", "RSP"}
    uninit_reads = analysis.read_regs - initialized_regs
    if uninit_reads:
        case["skip"] = True
        case["skip_reason"] = (
            f"instruction '{analysis.disasm_text}' reads uninitialized register(s): "
            + ", ".join(sorted(uninit_reads))
        )
        return case

    # Determine which registers to check (written regs ∩ initialized regs)
    # Exclude RSP/RBP: their values differ between Unicorn and the lifter test framework
    check_regs = analysis.written_regs & initialized_regs - {"RSP", "RBP", "RIP"}

    # Special handler overrides
    if handler in RAX_RDX_HANDLERS:
        check_regs = {"RAX", "RDX"}
    elif handler in EXTENSION_HANDLERS:
        check_regs = {"RAX"}
        if handler in ("cwd", "cdq", "cqo"):
            check_regs.add("RDX")

    # Fallback: if instruction writes to a register we initialized, check it
    if not check_regs and handler not in FLAG_MANIP_HANDLERS and handler not in FLAG_ONLY_HANDLERS:
        # Check RAX as default destination
        if "RAX" in initialized_regs:
            check_regs = {"RAX"}

    # Determine which flags to check
    check_flags: List[str] = []
    if handler in FLAG_MANIP_HANDLERS:
        check_flags = FLAG_MANIP_HANDLERS[handler]
        check_regs = set()
    elif handler in NO_FLAG_HANDLERS:
        check_flags = []
    elif handler in FLAG_ONLY_HANDLERS:
        check_flags = ARITH_FLAGS
    elif analysis.writes_flags:
        check_flags = ARITH_FLAGS

    # Build enriched case
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
        if cases[i].get("skip"):
            skipped += 1
        elif cases[i].get("oracle") != before_oracle:
            enriched += 1

    payload["cases"] = cases
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"Enriched: {enriched} cases, Skipped: {skipped} cases")
    print(f"Total: {len(cases)} cases")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
