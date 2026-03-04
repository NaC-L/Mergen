#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    return text


def parse_opcode_table(path: Path) -> Tuple[Dict[str, List[str]], Dict[str, Set[str]]]:
    raw = path.read_text(encoding="utf-8")
    text = strip_comments(raw)

    handlers: Dict[str, List[str]] = {}
    mnemonic_to_handlers: Dict[str, Set[str]] = {}

    for match in re.finditer(r"OPCODE\((.*?)\)", text, flags=re.DOTALL):
        body = match.group(1)
        tokens = [token.strip() for token in body.split(",") if token.strip()]
        if not tokens:
            continue

        handler = tokens[0].lower()
        mnemonics = [token.lower() for token in tokens[1:]]
        handlers[handler] = mnemonics

        for mnemonic in mnemonics:
            mnemonic_to_handlers.setdefault(mnemonic, set()).add(handler)

    return handlers, mnemonic_to_handlers


def parse_vector_signals(path: Path) -> dict:
    if not path.exists():
        return {
            "handlers": [],
            "skipped_handlers": [],
            "active_test_names": [],
            "active_name_prefixes": [],
        }

    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        cases = []

    active_handlers = set()
    skipped_handlers = set()
    active_names = []
    active_prefixes = set()

    for case in cases:
        if not isinstance(case, dict):
            continue

        handler = str(case.get("handler", "")).strip().lower()
        is_skipped = bool(case.get("skip"))
        if handler:
            if is_skipped:
                skipped_handlers.add(handler)
            else:
                active_handlers.add(handler)

        if is_skipped:
            continue

        name = str(case.get("name", "")).strip()
        if name:
            active_names.append(name)
            active_prefixes.add(name.split("_", 1)[0].lower())

    return {
        "handlers": sorted(active_handlers),
        "skipped_handlers": sorted(skipped_handlers),
        "active_test_names": active_names,
        "active_name_prefixes": sorted(active_prefixes),
    }


def parse_legacy_test_signals(path: Path) -> dict:
    if not path.exists():
        return {
            "test_names": [],
            "name_prefixes": [],
            "byte_comment_mnemonics": [],
        }

    text = path.read_text(encoding="utf-8")

    names = re.findall(r'\.name\s*=\s*"([^"]+)"', text)
    name_prefixes = {name.split("_", 1)[0].lower() for name in names if name}

    byte_comments = set(
        m.lower()
        for m in re.findall(
            r"instructionBytes\s*=\s*\{[^}]+\}\s*,\s*//\s*([A-Za-z0-9_]+)",
            text,
        )
    )

    return {
        "test_names": names,
        "name_prefixes": sorted(name_prefixes),
        "byte_comment_mnemonics": sorted(byte_comments),
    }


def compute_coverage(
    handlers: Dict[str, List[str]],
    mnemonic_to_handlers: Dict[str, Set[str]],
    vector_signals: dict,
    legacy_signals: dict,
) -> dict:
    opcode_handlers = set(handlers.keys())
    covered_handlers = set(vector_signals["handlers"]) & opcode_handlers
    skipped_handlers = set(vector_signals.get("skipped_handlers", [])) & opcode_handlers

    for prefix in vector_signals.get("active_name_prefixes", []):
        if prefix in handlers:
            covered_handlers.add(prefix)

    for prefix in legacy_signals["name_prefixes"]:
        if prefix in handlers:
            covered_handlers.add(prefix)

    for mnemonic in legacy_signals["byte_comment_mnemonics"]:
        for handler in mnemonic_to_handlers.get(mnemonic, []):
            if handler in opcode_handlers:
                covered_handlers.add(handler)

    missing_handlers = sorted(opcode_handlers - covered_handlers - skipped_handlers)

    return {
        "total_handlers": len(opcode_handlers),
        "covered_handlers": len(covered_handlers),
        "skipped_handlers": len(skipped_handlers),
        "coverage_percent": round(
            (len(covered_handlers) * 100.0 / max(1, len(opcode_handlers))), 2
        ),
        "covered_list": sorted(covered_handlers),
        "skipped_list": sorted(skipped_handlers),
        "missing_list": missing_handlers,
    }


def build_report(handlers: Dict[str, List[str]], coverage: dict) -> str:
    lines = []
    lines.append("Instruction handler coverage report")
    lines.append("===================================")
    lines.append(
        f"Covered {coverage['covered_handlers']} / {coverage['total_handlers']} handlers "
        f"({coverage['coverage_percent']}%)"
    )
    lines.append(f"Skipped handlers: {coverage['skipped_handlers']}")
    lines.append("")
    lines.append("Missing handlers:")

    for handler in coverage["missing_list"]:
        mnemonics = handlers.get(handler, [])
        if mnemonics:
            lines.append(f"- {handler}: {', '.join(mnemonics)}")
        else:
            lines.append(f"- {handler}: (no explicit mnemonic list)")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Collect instruction test coverage against x86_64_opcodes.x"
    )
    parser.add_argument(
        "--opcode-file",
        default="lifter/x86_64_opcodes.x",
        help="Path to opcode dispatch table",
    )
    parser.add_argument(
        "--vectors-file",
        default="lifter/test_vectors/oracle_vectors.json",
        help="Path to generated oracle vectors JSON",
    )
    parser.add_argument(
        "--legacy-tests-file",
        default="lifter/test_instructions.cpp",
        help="Optional legacy source file for extra signal extraction",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output instead of human-readable report",
    )
    args = parser.parse_args()

    opcode_path = Path(args.opcode_file)
    vectors_path = Path(args.vectors_file)
    legacy_path = Path(args.legacy_tests_file)

    handlers, mnemonic_to_handlers = parse_opcode_table(opcode_path)
    vector_signals = parse_vector_signals(vectors_path)
    legacy_signals = parse_legacy_test_signals(legacy_path)
    coverage = compute_coverage(
        handlers, mnemonic_to_handlers, vector_signals, legacy_signals
    )

    payload = {
        "opcode_file": str(opcode_path),
        "vectors_file": str(vectors_path),
        "legacy_tests_file": str(legacy_path),
        "coverage": coverage,
        "vector_signals": vector_signals,
        "legacy_signals": legacy_signals,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return

    print(build_report(handlers, coverage))


if __name__ == "__main__":
    main()
