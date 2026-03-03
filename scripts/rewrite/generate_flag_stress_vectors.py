#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

DEFAULT_INPUT_VECTORS = Path("lifter/test_vectors/oracle_vectors_full_handlers.json")
DEFAULT_OUTPUT_VECTORS = Path("lifter/test_vectors/oracle_vectors_flagstress.json")
DEFAULT_SEMANTICS = Path("lifter/Semantics.ipp")

DEFAULT_CODE_ADDRESS = 0x1000000
DEFAULT_STACK_ADDRESS = 0x2000000
DEFAULT_STACK_SIZE = 0x20000
DEFAULT_CODE_SIZE = 0x1000
DEFAULT_DATA_ADDRESS = 0x3000000
DEFAULT_DATA_SIZE = 0x40000

FLAG_BITS = {
    "FLAG_CF": 0,
    "FLAG_PF": 2,
    "FLAG_AF": 4,
    "FLAG_ZF": 6,
    "FLAG_SF": 7,
    "FLAG_TF": 8,
    "FLAG_IF": 9,
    "FLAG_DF": 10,
    "FLAG_OF": 11,
}

REGISTER_ALIASES = {
    "RIP": "UC_X86_REG_RIP",
    "RSP": "UC_X86_REG_RSP",
    "RBP": "UC_X86_REG_RBP",
    "RAX": "UC_X86_REG_RAX",
    "RBX": "UC_X86_REG_RBX",
    "RCX": "UC_X86_REG_RCX",
    "RDX": "UC_X86_REG_RDX",
    "RSI": "UC_X86_REG_RSI",
    "RDI": "UC_X86_REG_RDI",
    "R8": "UC_X86_REG_R8",
    "R9": "UC_X86_REG_R9",
    "R10": "UC_X86_REG_R10",
    "R11": "UC_X86_REG_R11",
    "R12": "UC_X86_REG_R12",
    "R13": "UC_X86_REG_R13",
    "R14": "UC_X86_REG_R14",
    "R15": "UC_X86_REG_R15",
    "RFLAGS": "UC_X86_REG_EFLAGS",
}

CORE_REGISTERS = [
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "RBP",
]

FLAG_PATTERNS = [
    {},
    {"FLAG_CF": 1},
    {"FLAG_ZF": 1, "FLAG_SF": 1, "FLAG_OF": 1},
    {"FLAG_PF": 1, "FLAG_AF": 1, "FLAG_DF": 1},
]

FLAGSTRESS_HANDLER_OVERRIDES: Dict[str, List[int]] = {
    # Register-only forms to avoid memory-dependent symbolic behavior in lifter tests.
    "blsi": [0xC4, 0x62, 0x60, 0xF3, 0xDF],
    "blsr": [0xC4, 0xC2, 0xA0, 0xF3, 0xCC],
    "blsmsk": [0xC4, 0xA2, 0xB0, 0xF3, 0xD6],
}


class FlagStressError(RuntimeError):
    pass


@dataclass
class OracleResult:
    flags: Dict[str, int]


class UnicornOracle:
    def __init__(self) -> None:
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # type: ignore
            from unicorn.x86_const import UC_X86_REG_EFLAGS  # type: ignore
            import unicorn.x86_const as ux  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise FlagStressError(
                "Unicorn is required. Install with `pip install unicorn`."
            ) from exc

        self._Uc = Uc
        self._UC_ARCH_X86 = UC_ARCH_X86
        self._UC_MODE_64 = UC_MODE_64
        self._UC_X86_REG_EFLAGS = UC_X86_REG_EFLAGS
        self._ux = ux

    def _resolve_reg_id(self, reg_name: str) -> int:
        alias = REGISTER_ALIASES.get(reg_name.upper())
        if alias is None:
            raise FlagStressError(f"Unsupported register '{reg_name}'")
        try:
            return int(getattr(self._ux, alias))
        except AttributeError as exc:
            raise FlagStressError(f"Missing Unicorn register constant for '{reg_name}'") from exc

    def emulate_flags(self, case: dict, requested_flags: Iterable[str]) -> OracleResult:
        instruction_bytes = bytes(case["instruction_bytes"])
        if not instruction_bytes:
            raise FlagStressError(f"Case '{case['name']}' has empty instruction bytes")

        uc = self._Uc(self._UC_ARCH_X86, self._UC_MODE_64)
        uc.mem_map(DEFAULT_CODE_ADDRESS, DEFAULT_CODE_SIZE)
        uc.mem_map(DEFAULT_STACK_ADDRESS, DEFAULT_STACK_SIZE)
        uc.mem_map(DEFAULT_DATA_ADDRESS, DEFAULT_DATA_SIZE)
        uc.mem_write(DEFAULT_CODE_ADDRESS, instruction_bytes)

        # Initialize data region with deterministic non-zero bytes.
        uc.mem_write(DEFAULT_DATA_ADDRESS, bytes((i * 17 + 11) & 0xFF for i in range(4096)))

        initial = case.get("initial", {})
        initial_registers = initial.get("registers", {})
        initial_flags = initial.get("flags", {})

        uc.reg_write(self._resolve_reg_id("RIP"), DEFAULT_CODE_ADDRESS)
        uc.reg_write(self._resolve_reg_id("RSP"), DEFAULT_STACK_ADDRESS + DEFAULT_STACK_SIZE - 0x200)

        for reg in CORE_REGISTERS:
            uc.reg_write(self._resolve_reg_id(reg), DEFAULT_DATA_ADDRESS + 0x1000)

        for reg_name, value in initial_registers.items():
            val = int(value, 0) if isinstance(value, str) else int(value)
            uc.reg_write(self._resolve_reg_id(reg_name), val)

        eflags = uc.reg_read(self._UC_X86_REG_EFLAGS)
        for flag_name, bit_value in initial_flags.items():
            bit = FLAG_BITS.get(flag_name)
            if bit is None:
                continue
            if int(bit_value) != 0:
                eflags |= (1 << bit)
            else:
                eflags &= ~(1 << bit)
        uc.reg_write(self._UC_X86_REG_EFLAGS, eflags)

        uc.emu_start(DEFAULT_CODE_ADDRESS, DEFAULT_CODE_ADDRESS + len(instruction_bytes), count=1)

        final_eflags = int(uc.reg_read(self._UC_X86_REG_EFLAGS))
        out_flags: Dict[str, int] = {}
        for flag_name in requested_flags:
            bit = FLAG_BITS.get(flag_name)
            if bit is None:
                raise FlagStressError(f"Unsupported requested flag '{flag_name}'")
            out_flags[flag_name] = 1 if ((final_eflags >> bit) & 1) else 0

        return OracleResult(flags=out_flags)


def parse_flag_writing_handlers(semantics_text: str) -> Dict[str, List[str]]:
    fn_pat = re.compile(
        r"MERGEN_LIFTER_DEFINITION_TEMPLATES\(void\)::lift_([A-Za-z0-9_]+)\(\)\s*\{",
        re.MULTILINE,
    )
    setflag_pat = re.compile(r"setFlag\(\s*(FLAG_[A-Z0-9_]+)\s*,")

    handlers: Dict[str, List[str]] = {}
    for match in fn_pat.finditer(semantics_text):
        handler = match.group(1).lower()
        start = match.end()

        depth = 1
        i = start
        while i < len(semantics_text) and depth > 0:
            ch = semantics_text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1

        body = semantics_text[start : max(start, i - 1)]
        flags = sorted(set(setflag_pat.findall(body)))
        if flags:
            handlers[handler] = flags

    return handlers


def deterministic_rng(handler: str, variant: int, seed: int) -> random.Random:
    digest = hashlib.sha256(f"{handler}:{variant}:{seed}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "little"))


def build_initial_state(handler: str, variant: int, seed: int) -> dict:
    rng = deterministic_rng(handler, variant, seed)

    registers = {
        reg: f"0x{(DEFAULT_DATA_ADDRESS + rng.randrange(0x200, 0x2000, 8)):x}"
        for reg in CORE_REGISTERS
    }

    registers["RSP"] = f"0x{(DEFAULT_STACK_ADDRESS + DEFAULT_STACK_SIZE - 0x200 - variant * 0x10):x}"
    registers["RCX"] = f"0x{[0, 1, 2, 7, 31, 63][variant % 6]:x}"
    registers["RAX"] = f"0x{(rng.getrandbits(64) ^ 0x1122334455667788):x}"
    registers["RDX"] = f"0x{(rng.getrandbits(64) ^ 0x8877665544332211):x}"

    flags = dict(FLAG_PATTERNS[variant % len(FLAG_PATTERNS)])
    return {"registers": registers, "flags": flags}


def pick_representative_cases(cases: List[dict]) -> Dict[str, dict]:
    by_handler: Dict[str, List[dict]] = {}
    for case in cases:
        handler = str(case.get("handler", "")).strip().lower()
        if not handler:
            continue
        by_handler.setdefault(handler, []).append(case)

    selected: Dict[str, dict] = {}
    for handler, candidates in by_handler.items():
        best = None
        for case in candidates:
            if case.get("skip"):
                continue
            best = case
            # prefer cases that already have strict flag expectations
            flags = case.get("expected", {}).get("flags", {})
            if isinstance(flags, dict) and flags:
                break
        if best is not None:
            selected[handler] = best

    return selected


def build_flag_case(base_case: dict, handler: str, flags: List[str], variant: int, seed: int) -> dict:
    case_name = f"flagstress_{handler}_{variant:02d}"
    initial = build_initial_state(handler, variant, seed)

    instruction_bytes = FLAGSTRESS_HANDLER_OVERRIDES.get(
        handler, list(base_case["instruction_bytes"])
    )

    return {
        "name": case_name,
        "handler": handler,
        "instruction_bytes": instruction_bytes,
        "initial": initial,
        "expected": {"registers": {}, "flags": {flag: None for flag in flags}},
        "oracle_mode": "unicorn",
        "source": "flag-stress-generator",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate strict flag-stress oracle vectors")
    parser.add_argument("--in-vectors", default=str(DEFAULT_INPUT_VECTORS))
    parser.add_argument("--out-vectors", default=str(DEFAULT_OUTPUT_VECTORS))
    parser.add_argument("--semantics", default=str(DEFAULT_SEMANTICS))
    parser.add_argument("--variants-per-handler", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1337)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    in_vectors = Path(args.in_vectors)
    out_vectors = Path(args.out_vectors)
    semantics_path = Path(args.semantics)

    payload = json.loads(in_vectors.read_text(encoding="utf-8"))
    if payload.get("schema") != "mergen-oracle-v1":
        raise FlagStressError("Input vectors schema must be 'mergen-oracle-v1'")

    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise FlagStressError("Input vectors must contain non-empty 'cases'")

    semantics_text = semantics_path.read_text(encoding="utf-8", errors="ignore")
    handler_flags = parse_flag_writing_handlers(semantics_text)
    reps = pick_representative_cases(cases)

    oracle = UnicornOracle()

    generated_cases: List[dict] = []
    skipped_generated = 0

    for handler, flags in sorted(handler_flags.items()):
        base_case = reps.get(handler)
        if base_case is None:
            continue

        for variant in range(max(1, args.variants_per_handler)):
            case = build_flag_case(base_case, handler, flags, variant, args.seed)
            try:
                result = oracle.emulate_flags(case, flags)
                case["expected"]["flags"] = result.flags
                case["oracle_observations"] = {"unicorn": {"flags": result.flags, "registers": {}}}
            except Exception as exc:
                case["skip"] = True
                case["skip_reason"] = f"oracle error: {exc}"
                skipped_generated += 1
            generated_cases.append(case)

    output_cases = [copy.deepcopy(case) for case in cases] + generated_cases

    output_payload = {
        "schema": "mergen-oracle-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_seed_schema": payload.get("source_seed_schema", "mergen-oracle-v1"),
        "providers": ["unicorn"],
        "cases": output_cases,
    }

    out_vectors.parent.mkdir(parents=True, exist_ok=True)
    out_vectors.write_text(json.dumps(output_payload, indent=2) + "\n", encoding="utf-8")

    generated_by_handler = len({c["handler"] for c in generated_cases})
    print(f"Generated flag stress vectors: {out_vectors}")
    print(f"Base cases retained: {len(cases)}")
    print(
        f"Generated flag cases: {len(generated_cases)} "
        f"across {generated_by_handler} handlers (skipped during oracle emulation: {skipped_generated})"
    )
    print(f"Total cases: {len(output_cases)}")


if __name__ == "__main__":
    main()
