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
import os
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
# These are now tested with computed assertions - no longer skipped.

# Conditional-jump handlers: maps handler name -> (condition_lambda, description).
# condition_lambda(flags_dict) -> bool (True = branch taken).
# flags_dict values are 0 or 1 integers.
JCC_HANDLERS = {
    "jz":   lambda f: f.get("FLAG_ZF", 0) == 1,
    "jnz":  lambda f: f.get("FLAG_ZF", 0) == 0,
    "jb":   lambda f: f.get("FLAG_CF", 0) == 1,
    "jnb":  lambda f: f.get("FLAG_CF", 0) == 0,
    "jbe":  lambda f: f.get("FLAG_CF", 0) == 1 or f.get("FLAG_ZF", 0) == 1,
    "jnbe": lambda f: f.get("FLAG_CF", 0) == 0 and f.get("FLAG_ZF", 0) == 0,
    "jl":   lambda f: f.get("FLAG_SF", 0) != f.get("FLAG_OF", 0),
    "jnl":  lambda f: f.get("FLAG_SF", 0) == f.get("FLAG_OF", 0),
    "jle":  lambda f: f.get("FLAG_ZF", 0) == 1 or f.get("FLAG_SF", 0) != f.get("FLAG_OF", 0),
    "jnle": lambda f: f.get("FLAG_ZF", 0) == 0 and f.get("FLAG_SF", 0) == f.get("FLAG_OF", 0),
    "js":   lambda f: f.get("FLAG_SF", 0) == 1,
    "jns":  lambda f: f.get("FLAG_SF", 0) == 0,
    "jo":   lambda f: f.get("FLAG_OF", 0) == 1,
    "jno":  lambda f: f.get("FLAG_OF", 0) == 0,
    "jp":   lambda f: f.get("FLAG_PF", 0) == 1,
    "jnp":  lambda f: f.get("FLAG_PF", 0) == 0,
}

# Handlers with computed register-side-effect assertions (no Unicorn needed).
# Each maps handler_name -> function(initial) -> {registers: {}, flags: {}}.
STACKP_VALUE = 0x14FEA0

def _parse_int(v, default=0):
    """Parse a value that may be int, hex string, or decimal string."""
    if v is None:
        return default
    if isinstance(v, int):
        return v
    return int(str(v), 0)


def _get_initial_register(initial: dict, name: str, default: Optional[int] = None) -> int:
    regs = initial.get("registers", {})
    if not isinstance(regs, dict):
        raise ValueError("initial.registers must be an object")
    if name in regs:
        return _parse_int(regs[name])
    if default is not None:
        return default
    raise ValueError(f"missing required initial register '{name}'")


def _get_initial_flag(initial: dict, name: str, default: Optional[int] = None) -> int:
    flags = initial.get("flags", {})
    if not isinstance(flags, dict):
        raise ValueError("initial.flags must be an object")
    if name in flags:
        return _parse_int(flags[name])
    if default is not None:
        return default
    raise ValueError(f"missing required initial flag '{name}'")


def _compute_push(initial):
    rsp = _get_initial_register(initial, "RSP", STACKP_VALUE)
    return {"registers": {"RSP": hex(rsp - 8)}, "flags": {}}


def _compute_pop(initial):
    rsp = _get_initial_register(initial, "RSP", STACKP_VALUE)
    return {"registers": {"RSP": hex(rsp + 8)}, "flags": {}}


def _compute_pushfq(initial):
    rsp = _get_initial_register(initial, "RSP", STACKP_VALUE)
    return {"registers": {"RSP": hex(rsp - 8)}, "flags": {}}


def _compute_popfq(initial):
    rsp = _get_initial_register(initial, "RSP", STACKP_VALUE)
    return {"registers": {"RSP": hex(rsp + 8)}, "flags": {}}


def _compute_leave(initial):
    rbp = _get_initial_register(initial, "RBP")
    return {"registers": {"RSP": hex(rbp + 8)}, "flags": {}}


def _compute_call(initial):
    rsp = _get_initial_register(initial, "RSP", STACKP_VALUE)
    return {"registers": {"RSP": hex(rsp - 8)}, "flags": {}}


def _compute_jmp(_initial):
    # jmp doesn't modify registers or flags, just control flow
    return {"registers": {}, "flags": {}}


def _compute_movs_x(initial):
    rsi = _get_initial_register(initial, "RSI")
    rdi = _get_initial_register(initial, "RDI")
    df = _get_initial_flag(initial, "FLAG_DF", 0)
    step = -8 if df else 8  # movsq = 8 bytes
    return {"registers": {"RSI": hex(rsi + step), "RDI": hex(rdi + step)}, "flags": {}}


def _compute_stosx(initial):
    rdi = _get_initial_register(initial, "RDI")
    df = _get_initial_flag(initial, "FLAG_DF", 0)
    step = -8 if df else 8  # stosq = 8 bytes
    return {"registers": {"RDI": hex(rdi + step)}, "flags": {}}


def _compute_cli(_initial):
    return {"registers": {}, "flags": {"FLAG_IF": 0}}


COMPUTED_HANDLERS = {
    "push":   _compute_push,
    "pop":    _compute_pop,
    "pushfq": _compute_pushfq,
    "popfq":  _compute_popfq,
    "leave":  _compute_leave,
    "call":   _compute_call,
    # ret is excluded: non-real-return path crashes in solvePath (symbolic return addr)
    "jmp":    _compute_jmp,
    "movs_x": _compute_movs_x,
    "stosx":  _compute_stosx,
    "cli":    _compute_cli,
}

# Non-deterministic system instructions — truly untestable
NONDETERMINISTIC_HANDLERS = {"rdtsc", "cpuid"}

# Handlers to skip: nondeterministic + ret (crashes in solvePath with symbolic retaddr)
SKIP_HANDLERS = NONDETERMINISTIC_HANDLERS | {"ret"}

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

# Handlers where OF is undefined when shift/rotate count > 1.
# We exclude OF from checked flags for these handlers since the
# test oracle (Unicorn) and hardware may differ for count > 1.
UNDEFINED_OF_HANDLERS = {"shrd", "shld", "rcl", "rcr", "ror", "rol"}


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
    if not isinstance(expected, dict):
        raise ValueError(f"case '{case.get('name', '<unnamed>')}': expected must be an object")
    if expected.get("registers") or expected.get("flags") or ("branch_taken" in expected):
        return case

    # Conditional-jump handlers: compute branch_taken from initial flags
    if handler in JCC_HANDLERS:
        initial_flags = case.get("initial", {}).get("flags", {})
        if not isinstance(initial_flags, dict):
            raise ValueError(f"case '{case.get('name', '<unnamed>')}': initial.flags must be an object")
        # Convert flag values to int (may be hex strings or ints)
        flags_int = {}
        for k, v in initial_flags.items():
            flags_int[k] = _parse_int(v, 0)
        condition = JCC_HANDLERS[handler]
        taken = condition(flags_int)
        case["oracle"] = "computed"
        case["expected"] = {
            "registers": {},
            "flags": {},
            "branch_taken": taken,
        }
        return case

    # Computed-handler enrichment (stack, string, cli, call/ret/jmp)
    if handler in COMPUTED_HANDLERS:
        initial = case.get("initial", {})
        if not isinstance(initial, dict):
            raise ValueError(f"case '{case.get('name', '<unnamed>')}': initial must be an object")
        try:
            computed = COMPUTED_HANDLERS[handler](initial)
        except ValueError as exc:
            raise ValueError(f"case '{case.get('name', '<unnamed>')}': {exc}") from exc
        case["oracle"] = "computed"
        case["expected"] = computed
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

    # Skip instructions with memory operands (Unicorn needs mapped memory).
    # Exception: LEA uses memory-addressing syntax but never accesses memory.
    if analysis.has_memory_operand and handler != "lea":
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

    # Exclude OF for handlers where it is undefined for count > 1
    if handler in UNDEFINED_OF_HANDLERS and "FLAG_OF" in check_flags:
        check_flags = [f for f in check_flags if f != "FLAG_OF"]

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
    if payload.get("schema") != "mergen-oracle-seed-v1":
        raise SystemExit("Seed schema must be 'mergen-oracle-seed-v1'")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit("Seed payload must contain a 'cases' array")

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
    temp_out = out_path.with_name(out_path.name + ".tmp")
    temp_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_out, out_path)

    print(f"Enriched: {enriched} cases, Skipped: {skipped} cases")
    print(f"Total: {len(cases)} cases")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
