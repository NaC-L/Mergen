#!/usr/bin/env python3
import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

DEFAULT_CODE_ADDRESS = 0x1000000
DEFAULT_STACK_ADDRESS = 0x2000000
DEFAULT_STACK_SIZE = 0x20000
DEFAULT_CODE_SIZE = 0x1000

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


class OracleError(RuntimeError):
    pass


@dataclass
class OracleResult:
    registers: Dict[str, int]
    flags: Dict[str, int]


class OracleProvider:
    name = "base"

    def emulate(self, case: dict) -> OracleResult:
        raise NotImplementedError


class UnicornOracleProvider(OracleProvider):
    name = "unicorn"

    def __init__(self):
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # type: ignore
            from unicorn.x86_const import UC_X86_REG_EFLAGS  # type: ignore
            import unicorn.x86_const as ux  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise OracleError(
                "Unicorn provider requires `unicorn` Python package. "
                "Install with `pip install unicorn`."
            ) from exc

        self._Uc = Uc
        self._UC_ARCH_X86 = UC_ARCH_X86
        self._UC_MODE_64 = UC_MODE_64
        self._UC_X86_REG_EFLAGS = UC_X86_REG_EFLAGS
        self._ux = ux

    def _resolve_reg_id(self, reg_name: str) -> int:
        key = reg_name.upper()
        alias = REGISTER_ALIASES.get(key)
        if alias is None:
            raise OracleError(f"Unsupported register in seed: {reg_name}")

        try:
            return getattr(self._ux, alias)
        except AttributeError as exc:
            raise OracleError(f"Unicorn register constant missing for {reg_name}") from exc

    def emulate(self, case: dict) -> OracleResult:
        instruction_bytes = bytes(case["instruction_bytes"])
        if not instruction_bytes:
            raise OracleError(f"Case '{case['name']}' has no instruction bytes")

        uc = self._Uc(self._UC_ARCH_X86, self._UC_MODE_64)
        uc.mem_map(DEFAULT_CODE_ADDRESS, DEFAULT_CODE_SIZE)
        uc.mem_map(DEFAULT_STACK_ADDRESS, DEFAULT_STACK_SIZE)
        uc.mem_write(DEFAULT_CODE_ADDRESS, instruction_bytes)

        initial = case.get("initial", {})
        initial_registers = initial.get("registers", {})
        initial_flags = initial.get("flags", {})

        uc.reg_write(self._resolve_reg_id("RIP"), DEFAULT_CODE_ADDRESS)
        uc.reg_write(
            self._resolve_reg_id("RSP"),
            DEFAULT_STACK_ADDRESS + DEFAULT_STACK_SIZE - 0x80,
        )

        for reg_name, value in initial_registers.items():
            uc.reg_write(self._resolve_reg_id(reg_name), int(value, 0) if isinstance(value, str) else int(value))

        eflags = uc.reg_read(self._UC_X86_REG_EFLAGS)
        for flag_name, bit_value in initial_flags.items():
            bit = FLAG_BITS.get(flag_name)
            if bit is None:
                raise OracleError(f"Unsupported flag in seed: {flag_name}")
            if int(bit_value) != 0:
                eflags |= (1 << bit)
            else:
                eflags &= ~(1 << bit)
        uc.reg_write(self._UC_X86_REG_EFLAGS, eflags)

        uc.emu_start(DEFAULT_CODE_ADDRESS, DEFAULT_CODE_ADDRESS + len(instruction_bytes), count=1)

        expected_spec = case.get("expected", {})
        expected_registers = expected_spec.get("registers", {})
        expected_flags = expected_spec.get("flags", {})

        out_registers: Dict[str, int] = {}
        out_flags: Dict[str, int] = {}

        for reg_name in expected_registers.keys():
            out_registers[reg_name] = int(uc.reg_read(self._resolve_reg_id(reg_name)))

        final_eflags = int(uc.reg_read(self._UC_X86_REG_EFLAGS))
        for flag_name in expected_flags.keys():
            bit = FLAG_BITS.get(flag_name)
            if bit is None:
                raise OracleError(f"Unsupported expected flag in seed: {flag_name}")
            out_flags[flag_name] = 1 if ((final_eflags >> bit) & 1) else 0

        return OracleResult(registers=out_registers, flags=out_flags)


def load_seed(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "mergen-oracle-seed-v1":
        raise OracleError("Seed schema must be 'mergen-oracle-seed-v1'")
    if not isinstance(payload.get("cases"), list) or not payload["cases"]:
        raise OracleError("Seed file must contain non-empty 'cases' array")
    return payload


def normalize_expected(case: dict, oracle_result: OracleResult) -> dict:
    expected = case.get("expected", {})
    out = {
        "registers": {},
        "flags": {},
    }

    for reg_name in expected.get("registers", {}).keys():
        out["registers"][reg_name] = f"0x{oracle_result.registers[reg_name]:x}"

    for flag_name in expected.get("flags", {}).keys():
        out["flags"][flag_name] = int(oracle_result.flags[flag_name])

    return out


def compare_results(results: Dict[str, OracleResult], case_name: str):
    providers = list(results.keys())
    if len(providers) < 2:
        return

    baseline = results[providers[0]]
    for provider_name in providers[1:]:
        cur = results[provider_name]
        if baseline.registers != cur.registers or baseline.flags != cur.flags:
            raise OracleError(
                f"Oracle mismatch in case '{case_name}' between "
                f"{providers[0]} and {provider_name}"
            )


def build_output(seed_payload: dict, provider_names: List[str], output_cases: List[dict]) -> dict:
    return {
        "schema": "mergen-oracle-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_seed_schema": seed_payload["schema"],
        "providers": provider_names,
        "cases": output_cases,
    }


def create_provider(name: str) -> OracleProvider:
    normalized = name.strip().lower()
    if normalized == "unicorn":
        return UnicornOracleProvider()
    raise OracleError(f"Unsupported oracle provider '{name}'")


def main():
    parser = argparse.ArgumentParser(description="Generate instruction oracle vectors")
    parser.add_argument(
        "--seed",
        default="scripts/rewrite/oracle_seed_vectors.json",
        help="Seed input JSON",
    )
    parser.add_argument(
        "--out",
        default="lifter/test_vectors/oracle_vectors.json",
        help="Generated oracle output JSON",
    )
    parser.add_argument(
        "--providers",
        default="unicorn",
        help="Comma-separated oracle providers (currently: unicorn)",
    )
    args = parser.parse_args()

    seed_path = Path(args.seed)
    out_path = Path(args.out)
    seed_payload = load_seed(seed_path)

    provider_names = [name.strip() for name in args.providers.split(",") if name.strip()]
    if not provider_names:
        raise OracleError("At least one provider is required")

    providers = [create_provider(name) for name in provider_names]

    output_cases = []
    for case in seed_payload["cases"]:
        handler_name = str(case.get("handler", "")).strip().lower()
        if not handler_name:
            raise OracleError(f"Case '{case['name']}' is missing required 'handler'")
        oracle_mode = str(case.get("oracle", "unicorn")).strip().lower()
        case_results: Dict[str, OracleResult] = {}
        if oracle_mode == "none":
            expected = case.get("expected", {})
            if not isinstance(expected, dict):
                raise OracleError(
                    f"Case '{case['name']}' has invalid expected payload for oracle=none"
                )
            expected.setdefault("registers", {})
            expected.setdefault("flags", {})
        elif oracle_mode == "unicorn":
            emulation_failed = False
            emulation_error = ""
            for provider in providers:
                try:
                    case_results[provider.name] = provider.emulate(case)
                except Exception as exc:
                    emulation_error = str(exc)
                    print(
                        f"WARNING: emulation failed for case '{case['name']}' "
                        f"with provider '{provider.name}': {emulation_error}"
                    )
                    emulation_failed = True
                    break

            if emulation_failed:
                expected = case.get("expected", {})
                expected.setdefault("registers", {})
                expected.setdefault("flags", {})
                oracle_mode = "none"
                case["skip"] = True
                case["skip_reason"] = f"emulation failed: {emulation_error}"
            else:
                compare_results(case_results, case["name"])
                consensus = case_results[providers[0].name]
                expected = normalize_expected(case, consensus)
        else:
            raise OracleError(
                f"Case '{case['name']}' has unsupported oracle mode '{oracle_mode}'"
            )

        output_case = {
            "name": case["name"],
            "handler": handler_name,
            "oracle_mode": oracle_mode,
            "instruction_bytes": case["instruction_bytes"],
            "initial": case.get("initial", {}),
            "expected": expected,
            "oracle_observations": {
                provider_name: {
                    "registers": {
                        reg: f"0x{value:x}"
                        for reg, value in result.registers.items()
                    },
                    "flags": result.flags,
                }
                for provider_name, result in case_results.items()
            },
        }
        if case.get("skip"):
            output_case["skip"] = True
            if case.get("skip_reason"):
                output_case["skip_reason"] = str(case.get("skip_reason"))

        output_cases.append(output_case)

    output_payload = build_output(seed_payload, provider_names, output_cases)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output_payload, indent=2) + "\n", encoding="utf-8")
    print(f"Generated oracle vectors: {out_path}")
    print(f"Cases: {len(output_cases)} | Providers: {', '.join(provider_names)}")


if __name__ == "__main__":
    main()
