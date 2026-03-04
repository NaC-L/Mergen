#!/usr/bin/env python3
"""Report handler test coverage from oracle vectors."""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List


def main():
    parser = argparse.ArgumentParser(description="Report handler test coverage")
    parser.add_argument(
        "--vectors",
        default="lifter/test_vectors/oracle_vectors.json",
        help="Oracle vectors JSON path",
    )
    parser.add_argument(
        "--opcodes",
        default="lifter/x86_64_opcodes.x",
        help="Opcode handler definition file",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    vectors_path = Path(args.vectors)
    opcodes_path = Path(args.opcodes)

    if not vectors_path.exists():
        print(f"ERROR: vectors file not found: {vectors_path}", file=sys.stderr)
        return 1

    payload = json.loads(vectors_path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])

    # Parse opcode handlers
    import re
    opcodes_text = opcodes_path.read_text(encoding="utf-8")
    opcodes_text = re.sub(r"/\*.*?\*/", "", opcodes_text, flags=re.DOTALL)
    opcodes_text = re.sub(r"//.*", "", opcodes_text)
    all_handlers = set()
    for match in re.finditer(r"OPCODE\((.*?)\)", opcodes_text, flags=re.DOTALL):
        tokens = [t.strip() for t in match.group(1).split(",") if t.strip()]
        if tokens:
            all_handlers.add(tokens[0].lower())

    # Categorize cases
    active_cases: List[dict] = []
    skipped_cases: List[dict] = []
    for case in cases:
        if case.get("skip"):
            skipped_cases.append(case)
        else:
            active_cases.append(case)

    # Active handlers: any non-skipped case with a handler name counts as coverage
    active_handlers: Dict[str, List[str]] = {}
    for case in active_cases:
        handler = case.get("handler", "").lower()
        if handler:
            active_handlers.setdefault(handler, []).append(case["name"])

    # Skipped handlers
    skipped_handler_set = {c.get("handler", "").lower() for c in skipped_cases}

    # Coverage
    covered = set(active_handlers.keys())
    uncovered = all_handlers - covered - skipped_handler_set
    total_handlers = len(all_handlers)
    covered_count = len(covered)
    skipped_count = len(skipped_handler_set & all_handlers)
    uncovered_count = len(uncovered)

    if args.json:
        report = {
            "total_handlers": total_handlers,
            "covered": covered_count,
            "skipped": skipped_count,
            "uncovered": uncovered_count,
            "active_cases": len(active_cases),
            "skipped_cases": len(skipped_cases),
            "coverage_pct": round(covered_count / total_handlers * 100, 1) if total_handlers else 0,
            "uncovered_handlers": sorted(uncovered),
            "skipped_handlers": sorted(skipped_handler_set & all_handlers),
        }
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print("Mergen Handler Test Coverage Report")
        print("=" * 60)
        print(f"Total handlers in x86_64_opcodes.x: {total_handlers}")
        print(f"Covered (active with oracle):       {covered_count} ({covered_count/total_handlers*100:.0f}%)")
        print(f"Skipped (need special setup):       {skipped_count}")
        print(f"Uncovered (no test case):           {uncovered_count}")
        print(f"Active test cases:                  {len(active_cases)}")
        print(f"Skipped test cases:                 {len(skipped_cases)}")
        print()

        if uncovered:
            print("UNCOVERED HANDLERS:")
            for h in sorted(uncovered):
                print(f"  - {h}")
            print()

        if skipped_handler_set & all_handlers:
            print("SKIPPED HANDLERS (need special test setup):")
            for h in sorted(skipped_handler_set & all_handlers):
                reasons = [c.get("skip_reason", "no reason") for c in skipped_cases
                           if c.get("handler", "").lower() == h]
                reason = reasons[0] if reasons else "unknown"
                print(f"  - {h}: {reason}")
            print()

        print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
