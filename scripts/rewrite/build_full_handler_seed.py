#!/usr/bin/env python3
import argparse
import json
import random
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

MNEMONIC_ALIAS = {
    "jae": "jnb",
    "jnae": "jb",
    "jna": "jbe",
    "ja": "jnbe",
    "jnge": "jl",
    "jge": "jnl",
    "jg": "jnle",
    "jng": "jle",
    "jpe": "jp",
    "jpo": "jnp",
    "je": "jz",
    "jne": "jnz",
    "sete": "setz",
    "setne": "setnz",
    "setae": "setnb",
    "setna": "setbe",
    "seta": "setnbe",
    "setge": "setnl",
    "setg": "setnle",
    "setpe": "setp",
    "setpo": "setnp",
    "cmovae": "cmovnb",
    "cmovna": "cmovbe",
    "cmova": "cmovnbe",
    "cmovge": "cmovnl",
    "cmovg": "cmovnle",
    "cmovpe": "cmovp",
    "cmovpo": "cmovnp",
}

MANUAL_HANDLER_CASES = {
    "imul2": {
        "mnemonic": "imul",
        "instruction_bytes": [0x48, 0xF7, 0xE9],
        "initial": {
            "registers": {"RAX": "0x7", "RDX": "0x0", "RCX": "0x3"},
            "flags": {},
        },
    },
    "mul2": {
        "mnemonic": "mul",
        "instruction_bytes": [0x48, 0xF7, 0xE1],
        "initial": {
            "registers": {"RAX": "0x7", "RDX": "0x0", "RCX": "0x3"},
            "flags": {},
        },
    },
    "div2": {
        "mnemonic": "div",
        "instruction_bytes": [0x48, 0xF7, 0xF1],
        "initial": {
            "registers": {"RAX": "0x10", "RDX": "0x0", "RCX": "0x2"},
            "flags": {},
        },
    },
    "idiv2": {
        "mnemonic": "idiv",
        "instruction_bytes": [0x48, 0xF7, 0xF9],
        "initial": {
            "registers": {"RAX": "0x10", "RDX": "0x0", "RCX": "0x2"},
            "flags": {},
        },
    },
    "blsi": {
        "mnemonic": "blsi",
        "instruction_bytes": [0xC4, 0xE2, 0x40, 0xF3, 0x58, 0x80],
        "initial": {
            "registers": {
                "RAX": "0x1000",
                "RCX": "0x2000",
                "R14": "0x3000"
            },
            "flags": {},
        },
    },
    "blsr": {
        "mnemonic": "blsr",
        "instruction_bytes": [0xC4, 0xE2, 0x20, 0xF3, 0x09],
        "initial": {
            "registers": {
                "RAX": "0x1000",
                "RCX": "0x2000",
                "R14": "0x3000"
            },
            "flags": {},
        },
    },
    "blsmsk": {
        "mnemonic": "blsmsk",
        "instruction_bytes": [0xC4, 0x02, 0x20, 0xF3, 0x56, 0xE4],
        "initial": {
            "registers": {
                "RAX": "0x1000",
                "RCX": "0x2000",
                "R14": "0x3000"
            },
            "flags": {},
        },
    },
    "movs_x": {
        "mnemonic": "movsq",
        "instruction_bytes": [0x48, 0xA5],
        "initial": {
            "registers": {
                "RSI": "0x2000",
                "RDI": "0x3000",
                "RAX": "0x1122334455667788"
            },
            "flags": {"FLAG_DF": "0x0"},
        },
    },
}

# Instruction byte overrides for handlers whose auto-discovered encodings
# use registers outside the default initial set (RAX, RBX, RCX, RDX).
# Each maps handler_name -> [byte, ...].  The default initial state is used.
INSTRUCTION_OVERRIDES: Dict[str, list] = {
    "dec":   [0xFF, 0xC9],          # dec ecx
    "bsr":   [0x0F, 0xBD, 0xC3],    # bsr eax, ebx
    "btc":   [0x0F, 0xBB, 0xC8],    # btc eax, ecx
    "btr":   [0x0F, 0xB3, 0xC8],    # btr eax, ecx
    "bts":   [0x0F, 0xAB, 0xC8],    # bts eax, ecx
    "sar":   [0xD2, 0xF8],          # sar al, cl
    "andn":  [0xC4, 0xE2, 0x70, 0xF2, 0xC2],  # andn eax, ecx, edx
    "bextr": [0xC4, 0xE2, 0x70, 0xF7, 0xC2],  # bextr eax, edx, ecx
    "bzhi":  [0xC4, 0xE2, 0x70, 0xF5, 0xC2],  # bzhi eax, edx, ecx
    "pext":  [0xC4, 0xE2, 0x72, 0xF5, 0xC2],  # pext eax, ecx, edx
}

SKIP_RUN_HANDLERS = set()

DEFAULT_INITIAL = {
    "registers": {
        "RAX": "0x1122334455667788",
        "RBX": "0x8877665544332211",
        "RCX": "0x10",
        "RDX": "0x2",
    },
    "flags": {},
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    return text


def parse_handlers(opcode_file: Path) -> Dict[str, List[str]]:
    text = strip_comments(opcode_file.read_text(encoding="utf-8"))
    handlers: Dict[str, List[str]] = {}

    for match in re.finditer(r"OPCODE\((.*?)\)", text, flags=re.DOTALL):
        body = match.group(1)
        tokens = [token.strip() for token in body.split(",") if token.strip()]
        if not tokens:
            continue
        handler = tokens[0].lower()
        mnemonics = [token.lower() for token in tokens[1:]]
        handlers[handler] = mnemonics

    return handlers


def normalize_mnemonic(raw: str) -> str:
    m = raw.strip().lower()
    return MNEMONIC_ALIAS.get(m, m)


def load_base_seed(seed_path: Path) -> dict:
    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    if payload.get("schema") != "mergen-oracle-seed-v1":
        raise RuntimeError("Base seed schema mismatch")
    if not isinstance(payload.get("cases"), list):
        raise RuntimeError("Base seed has invalid cases array")
    return payload


def decode_first_insn(md: Cs, blob: bytes):
    decoded = list(md.disasm(blob, 0))
    if not decoded:
        return None
    return decoded[0]


def register_sample(samples: Dict[str, Dict[str, object]], mnemonic: str, insn) -> None:
    has_mem = "[" in insn.op_str
    raw_bytes = list(insn.bytes)
    current = samples.get(mnemonic)
    if current is None or (current.get("has_memory_operand", True) and not has_mem):
        samples[mnemonic] = {
            "instruction_bytes": raw_bytes,
            "has_memory_operand": has_mem,
        }


def discover_mnemonic_samples(
    targets: Set[str], iterations: int, bytes_per_iteration: int, seed: int
) -> Dict[str, Dict[str, object]]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    rng = random.Random(seed)
    samples: Dict[str, Dict[str, object]] = {}

    for _ in range(max(1, iterations)):
        unresolved = {mn for mn in targets if mn not in samples}
        if not unresolved:
            break

        blob = bytes(rng.getrandbits(8) for _ in range(max(1024, bytes_per_iteration)))

        offset = 0
        while offset < len(blob):
            insn = decode_first_insn(md, blob[offset : offset + 15])
            if insn is None:
                offset += 1
                continue

            mnemonic = normalize_mnemonic(insn.mnemonic)
            if mnemonic in unresolved:
                register_sample(samples, mnemonic, insn)

            offset += max(1, insn.size)

    return samples


def targeted_prefix_discovery(
    samples: Dict[str, Dict[str, object]],
    targets: Set[str],
    seed: int,
) -> None:
    unresolved = {mn for mn in targets if mn not in samples}
    if not unresolved:
        return

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    rng = random.Random(seed ^ 0xA5A5A5A5)

    def probe(candidate: bytes):
        insn = decode_first_insn(md, candidate)
        if insn is None:
            return
        mnemonic = normalize_mnemonic(insn.mnemonic)
        if mnemonic in targets:
            register_sample(samples, mnemonic, insn)

    # POPCNT/TZCNT/LZCNT families
    for opcode in (0xB8, 0xBC, 0xBD):
        for modrm in range(256):
            probe(bytes([0xF3, 0x0F, opcode, modrm]))

    # BLSI/BLSMSK/BLSR family
    for modrm in range(256):
        probe(bytes([0xF3, 0x0F, 0x38, 0xF3, modrm]))

    # BEXTR legacy-ish forms
    for prefix in (0xF2, 0xF3, 0x66):
        for modrm in range(256):
            for imm in (0x00, 0x01, 0x10, 0x20, 0x7F):
                probe(bytes([prefix, 0x0F, 0x38, 0xF7, modrm, imm]))

    # VEX-encoded probing for ANDN/BEXTR/BZHI/PEXT/PDEP family
    for opcode in (0xF2, 0xF5, 0xF7):
        for _ in range(300000):
            b1 = rng.getrandbits(8)
            b2 = rng.getrandbits(8)
            modrm = rng.getrandbits(8)
            imm = rng.getrandbits(8)
            probe(bytes([0xC4, b1, b2, opcode, modrm]))
            probe(bytes([0xC4, b1, b2, opcode, modrm, imm]))

            if all(mn in samples for mn in targets):
                return


def build_smoke_case(
    handler: str,
    mnemonic: str,
    instruction_bytes: List[int],
    initial: Optional[dict] = None,
    run_enabled: bool = True,
 ) -> dict:
    case = {
        "name": f"smoke_{handler}_{mnemonic}",
        "handler": handler,
        "instruction_bytes": instruction_bytes,
        "initial": initial if initial is not None else DEFAULT_INITIAL,
        "expected": {"registers": {}, "flags": {}},
        "oracle": "none",
        "source": "capstone-auto-discovery",
    }
    if not run_enabled:
        case["skip"] = True
        case["skip_reason"] = "known-crashing handler path"
    return case


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build full handler seed using Capstone auto-discovery"
    )
    parser.add_argument("--opcode-file", default="lifter/x86_64_opcodes.x")
    parser.add_argument("--base-seed", default="scripts/rewrite/oracle_seed_vectors.json")
    parser.add_argument("--out-seed", default="scripts/rewrite/oracle_seed_full_handlers.json")
    parser.add_argument("--iterations", type=int, default=12)
    parser.add_argument("--bytes-per-iteration", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    opcode_file = Path(args.opcode_file)
    base_seed_path = Path(args.base_seed)
    out_seed_path = Path(args.out_seed)

    handlers = parse_handlers(opcode_file)
    base_seed = load_base_seed(base_seed_path)

    covered_handlers = {
        str(case.get("handler", "")).strip().lower()
        for case in base_seed["cases"]
        if str(case.get("handler", "")).strip()
    }

    missing_handlers = sorted(set(handlers.keys()) - covered_handlers)

    target_mnemonics: Set[str] = set()
    for handler in missing_handlers:
        if handler in MANUAL_HANDLER_CASES:
            continue
        for mnemonic in handlers.get(handler, []):
            target_mnemonics.add(normalize_mnemonic(mnemonic))

    samples = discover_mnemonic_samples(
        targets=target_mnemonics,
        iterations=args.iterations,
        bytes_per_iteration=args.bytes_per_iteration,
        seed=args.seed,
    )
    targeted_prefix_discovery(samples, target_mnemonics, args.seed)

    auto_cases = []
    unresolved_handlers = []

    for handler in missing_handlers:
        if handler in MANUAL_HANDLER_CASES:
            manual = MANUAL_HANDLER_CASES[handler]
            auto_cases.append(
                build_smoke_case(
                    handler=handler,
                    mnemonic=manual["mnemonic"],
                    instruction_bytes=manual["instruction_bytes"],
                    initial=manual["initial"],
                    run_enabled=handler not in SKIP_RUN_HANDLERS,
                )
            )
            continue

        selected = None
        selected_mnemonic = None
        for mnemonic in handlers.get(handler, []):
            normalized = normalize_mnemonic(mnemonic)
            sample = samples.get(normalized)
            if sample is None:
                continue
            selected = sample
            selected_mnemonic = normalized
            if not sample.get("has_memory_operand", True):
                break

        if selected is None or selected_mnemonic is None:
            unresolved_handlers.append(handler)
            continue

        # Apply instruction byte override if available
        insn_bytes = list(selected["instruction_bytes"])
        if handler in INSTRUCTION_OVERRIDES:
            insn_bytes = list(INSTRUCTION_OVERRIDES[handler])

        auto_cases.append(
            build_smoke_case(
                handler=handler,
                mnemonic=selected_mnemonic,
                instruction_bytes=insn_bytes,
                run_enabled=handler not in SKIP_RUN_HANDLERS,
        )
        )

    if unresolved_handlers:
        unresolved = ", ".join(unresolved_handlers)
        raise RuntimeError(
            f"Failed to discover instruction bytes for handlers: {unresolved}"
        )

    merged_cases = list(base_seed["cases"]) + auto_cases

    output = {
        "schema": "mergen-oracle-seed-v1",
        "base_seed": str(base_seed_path),
        "generator": "build_full_handler_seed.py",
        "cases": merged_cases,
    }

    out_seed_path.parent.mkdir(parents=True, exist_ok=True)
    out_seed_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    final_handlers = {
        str(case.get("handler", "")).strip().lower()
        for case in merged_cases
        if str(case.get("handler", "")).strip()
    }

    print(f"Generated full-handler seed: {out_seed_path}")
    print(f"Base cases: {len(base_seed['cases'])} | Auto smoke cases: {len(auto_cases)}")
    print(f"Handler coverage in seed: {len(final_handlers)} / {len(handlers)}")


if __name__ == "__main__":
    main()
