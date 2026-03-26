#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from review_buckets import load_changed_paths, normalize_path


@dataclass(frozen=True)
class CheckResult:
    id: str
    status: str
    files: list[str]
    details: list[str]


_XMM_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{32}$")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run high-signal invariant checks for review")
    parser.add_argument("--base", default="main", help="Base revision")
    parser.add_argument("--head", default="HEAD", help="Head revision")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--paths",
        nargs="*",
        default=None,
        help="Optional explicit changed paths (bypasses git diff)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all invariant checks regardless of changed paths",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )
    return parser.parse_args()


def _read_text(repo_root: Path, rel_path: str) -> str:
    return (repo_root / rel_path).read_text(encoding="utf-8")


def _load_json(repo_root: Path, rel_path: str) -> object:
    raw = _read_text(repo_root, rel_path)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{rel_path} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from exc


def _contains_all(text: str, tokens: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for token in tokens:
        if token not in text:
            missing.append(token)
    return missing


def _check_backend_invariants(repo_root: Path) -> CheckResult:
    files = ["cmake/FindIced-Wrapper.cmake", "scripts/dev/configure_zydis.cmd"]
    details: list[str] = []

    try:
        find_iced = _read_text(repo_root, files[0])
        configure_zydis = _read_text(repo_root, files[1])
    except OSError as exc:
        return CheckResult(
            id="backend_invariants",
            status="FAIL",
            files=files,
            details=[f"failed to read backend files: {exc}"],
        )

    missing_find_iced = _contains_all(
        find_iced,
        (
            "remove_definitions(-DICED_FOUND -DICED_NOT_FOUND)",
            "if (BUILD_WITH_ZYDIS)",
            "set(ICED_NOT_FOUND TRUE CACHE BOOL",
            "set(ICED_FOUND FALSE CACHE BOOL",
            "add_compile_definitions(ICED_NOT_FOUND)",
            "if (DEFINED CARGO_EXECUTABLE AND NOT \"${CARGO_EXECUTABLE}\" STREQUAL \"\")",
            "if (EXISTS \"${CARGO_EXECUTABLE}\")",
            "set(_MERGEN_CARGO_EXECUTABLE \"${CARGO_EXECUTABLE}\")",
            "set(ICED_FOUND TRUE CACHE BOOL",
            "set(ICED_NOT_FOUND FALSE CACHE BOOL",
            "add_compile_definitions(ICED_FOUND)",
        ),
    )
    if missing_find_iced:
        details.append(
            "cmake/FindIced-Wrapper.cmake is missing required backend/cargo guard tokens: "
            + ", ".join(missing_find_iced)
        )

    missing_configure_zydis = _contains_all(
        configure_zydis,
        (
            "-UICED_*",
            "-UCARGO_EXECUTABLE",
            "-DBUILD_WITH_ZYDIS=ON",
            "if exist \"%BUILD_DIR%\\CMakeCache.txt\"",
        ),
    )
    if missing_configure_zydis:
        details.append(
            "scripts/dev/configure_zydis.cmd is missing backend cache hygiene tokens: "
            + ", ".join(missing_configure_zydis)
        )

    status = "PASS" if not details else "FAIL"
    if status == "PASS":
        details.append("Backend cache/cargo invariants satisfied")

    return CheckResult(id="backend_invariants", status=status, files=files, details=details)


def _validate_case_name(case_name: object, *, path: str, index: int) -> str:
    if not isinstance(case_name, str) or not case_name.strip():
        raise ValueError(f"{path} case[{index}] has invalid name {case_name!r}; expected non-empty string")
    return case_name.strip()


def _validate_skip(skip_value: object, *, path: str, index: int) -> bool:
    if not isinstance(skip_value, bool):
        raise ValueError(
            f"{path} case[{index}] has invalid 'skip' value {skip_value!r}; expected boolean"
        )
    return skip_value


def _validate_register_value(path: str, case_name: str, reg_name: str, value: object) -> list[str]:
    errors: list[str] = []

    if value is None:
        return errors

    if not isinstance(value, str):
        errors.append(
            f"{path} case '{case_name}' register '{reg_name}' has non-string value {value!r}; expected hex string"
        )
        return errors

    if reg_name.upper().startswith("XMM") and not _XMM_HEX_RE.fullmatch(value):
        errors.append(
            f"{path} case '{case_name}' register '{reg_name}' has non-128-bit value {value!r}; expected 0x + 32 hex digits"
        )

    return errors


def _extract_register_maps(case: dict) -> list[dict[str, object]]:
    maps: list[dict[str, object]] = []

    for section in ("initial", "expected"):
        payload = case.get(section)
        if isinstance(payload, dict):
            regs = payload.get("registers")
            if isinstance(regs, dict):
                maps.append(regs)

    oracle_observations = case.get("oracle_observations")
    if isinstance(oracle_observations, dict):
        for provider_payload in oracle_observations.values():
            if not isinstance(provider_payload, dict):
                continue
            regs = provider_payload.get("registers")
            if isinstance(regs, dict):
                maps.append(regs)

    return maps


def _check_vector_file(repo_root: Path, rel_path: str) -> CheckResult:
    details: list[str] = []
    try:
        payload = _load_json(repo_root, rel_path)
    except ValueError as exc:
        return CheckResult(id=f"vector_file:{rel_path}", status="FAIL", files=[rel_path], details=[str(exc)])
    except OSError as exc:
        return CheckResult(id=f"vector_file:{rel_path}", status="FAIL", files=[rel_path], details=[str(exc)])

    if not isinstance(payload, dict):
        return CheckResult(
            id=f"vector_file:{rel_path}",
            status="FAIL",
            files=[rel_path],
            details=[f"{rel_path} must be a JSON object"],
        )

    schema = payload.get("schema")
    filename = Path(rel_path).name
    if filename.startswith("oracle_vectors") and schema != "mergen-oracle-v1":
        details.append(
            f"{rel_path} has schema {schema!r}; expected 'mergen-oracle-v1'"
        )
    if filename == "oracle_seed_vectors.json" and schema != "mergen-oracle-seed-v1":
        details.append(
            f"{rel_path} has schema {schema!r}; expected 'mergen-oracle-seed-v1'"
        )

    cases = payload.get("cases")
    if not isinstance(cases, list):
        details.append(f"{rel_path} has invalid 'cases' field; expected array")
        return CheckResult(
            id=f"vector_file:{rel_path}",
            status="FAIL",
            files=[rel_path],
            details=details,
        )

    seen_names: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            details.append(f"{rel_path} case[{index}] must be an object")
            continue

        try:
            case_name = _validate_case_name(case.get("name"), path=rel_path, index=index)
        except ValueError as exc:
            details.append(str(exc))
            case_name = f"case_{index}"

        if case_name in seen_names:
            details.append(f"{rel_path} duplicate case name '{case_name}'")
        else:
            seen_names.add(case_name)

        if "skip" in case:
            try:
                _validate_skip(case.get("skip"), path=rel_path, index=index)
            except ValueError as exc:
                details.append(str(exc))

        handler_value = case.get("handler")
        if handler_value is not None and not isinstance(handler_value, str):
            details.append(
                f"{rel_path} case '{case_name}' has invalid handler {handler_value!r}; expected string"
            )

        for register_map in _extract_register_maps(case):
            for reg_name, value in register_map.items():
                details.extend(_validate_register_value(rel_path, case_name, str(reg_name), value))

    status = "PASS" if not details else "FAIL"
    if status == "PASS":
        details.append(f"{rel_path} passed schema/shape/register-width checks")

    return CheckResult(id=f"vector_file:{rel_path}", status=status, files=[rel_path], details=details)


def _validate_pattern_descriptor(sample_name: str, descriptor: object, rel_path: str, details: list[str]) -> None:
    if isinstance(descriptor, str):
        if not descriptor.strip():
            details.append(
                f"{rel_path} sample '{sample_name}' has empty string pattern descriptor"
            )
        return

    if isinstance(descriptor, dict) and "line_all" in descriptor:
        tokens = descriptor.get("line_all")
        if not isinstance(tokens, list) or not tokens:
            details.append(
                f"{rel_path} sample '{sample_name}' line_all descriptor must be a non-empty array"
            )
            return

        bad = [token for token in tokens if not isinstance(token, str) or not token.strip()]
        if bad:
            details.append(
                f"{rel_path} sample '{sample_name}' line_all descriptor contains empty/non-string token"
            )
        return

    details.append(
        f"{rel_path} sample '{sample_name}' has unsupported pattern descriptor {descriptor!r}"
    )


def _check_microtest_manifest(repo_root: Path, rel_path: str) -> CheckResult:
    details: list[str] = []
    try:
        payload = _load_json(repo_root, rel_path)
    except ValueError as exc:
        return CheckResult(id="microtest_manifest", status="FAIL", files=[rel_path], details=[str(exc)])
    except OSError as exc:
        return CheckResult(id="microtest_manifest", status="FAIL", files=[rel_path], details=[str(exc)])

    if not isinstance(payload, dict):
        return CheckResult(
            id="microtest_manifest",
            status="FAIL",
            files=[rel_path],
            details=[f"{rel_path} must be a JSON object with top-level 'samples' field"],
        )

    samples = payload.get("samples")
    if not isinstance(samples, list) or not samples:
        return CheckResult(
            id="microtest_manifest",
            status="FAIL",
            files=[rel_path],
            details=[f"{rel_path} must contain non-empty 'samples' array"],
        )

    seen_names: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            details.append(f"{rel_path} sample[{index}] must be an object")
            continue

        name = sample.get("name")
        if not isinstance(name, str) or not name.strip() or ".." in name or "/" in name or "\\" in name:
            details.append(
                f"{rel_path} sample[{index}] has invalid name {name!r}; expected safe non-empty basename"
            )
            sample_name = f"sample_{index}"
        else:
            sample_name = name.strip()

        if sample_name in seen_names:
            details.append(f"{rel_path} duplicate sample name '{sample_name}'")
        else:
            seen_names.add(sample_name)

        skip_value = sample.get("skip", False)
        if not isinstance(skip_value, bool):
            details.append(
                f"{rel_path} sample '{sample_name}' has invalid skip value {skip_value!r}; expected boolean"
            )
            is_skipped = False
        else:
            is_skipped = skip_value

        if "patterns" in sample:
            patterns = sample.get("patterns")
            if isinstance(patterns, str):
                details.append(
                    f"{rel_path} sample '{sample_name}' patterns must be an array; got string"
                )
            elif not isinstance(patterns, list):
                details.append(
                    f"{rel_path} sample '{sample_name}' patterns must be an array"
                )
            elif not patterns:
                if not is_skipped:
                    details.append(
                        f"{rel_path} sample '{sample_name}' patterns must not be empty unless skip=true"
                    )
            else:
                for descriptor in patterns:
                    _validate_pattern_descriptor(sample_name, descriptor, rel_path, details)

    status = "PASS" if not details else "FAIL"
    if status == "PASS":
        details.append(f"{rel_path} passed manifest shape and descriptor checks")

    return CheckResult(id="microtest_manifest", status=status, files=[rel_path], details=details)


def _collect_vector_targets(changed_paths: list[str], run_all: bool) -> list[str]:
    targets: set[str] = set()
    if run_all:
        targets.add("lifter/test/test_vectors/oracle_vectors.json")
        targets.add("lifter/test/test_vectors/oracle_vectors_full_handlers.json")
        targets.add("scripts/rewrite/oracle_seed_vectors.json")

    for path in changed_paths:
        normalized = normalize_path(path)
        if normalized.startswith("lifter/test/test_vectors/") and Path(normalized).name in {
            "oracle_vectors.json",
            "oracle_vectors_full_handlers.json",
        }:
            targets.add(normalized)
        if normalized == "scripts/rewrite/oracle_seed_vectors.json":
            targets.add(normalized)

    return sorted(targets)


def _should_run_backend(changed_paths: list[str], run_all: bool) -> bool:
    if run_all:
        return True
    for path in changed_paths:
        normalized = normalize_path(path)
        if normalized in {
            "cmake/FindIced-Wrapper.cmake",
            "scripts/dev/configure_zydis.cmd",
            "scripts/dev/configure_iced.cmd",
        }:
            return True
    return False


def _should_run_manifest(changed_paths: list[str], run_all: bool) -> bool:
    if run_all:
        return True
    return any(
        normalize_path(path) == "scripts/rewrite/instruction_microtests.json"
        for path in changed_paths
    )


def run_invariant_guard(repo_root: Path, changed_paths: list[str], run_all: bool) -> list[CheckResult]:
    results: list[CheckResult] = []

    if _should_run_backend(changed_paths, run_all):
        results.append(_check_backend_invariants(repo_root))

    for target in _collect_vector_targets(changed_paths, run_all):
        results.append(_check_vector_file(repo_root, target))

    if _should_run_manifest(changed_paths, run_all):
        results.append(_check_microtest_manifest(repo_root, "scripts/rewrite/instruction_microtests.json"))

    if not results:
        results.append(
            CheckResult(
                id="no_checks_selected",
                status="SKIP",
                files=[],
                details=["No invariant checks selected for changed files"],
            )
        )

    return results


def _payload(results: list[CheckResult]) -> dict:
    return {
        "total_checks": len(results),
        "failed": [result.id for result in results if result.status == "FAIL"],
        "results": [
            {
                "id": result.id,
                "status": result.status,
                "files": result.files,
                "details": result.details,
            }
            for result in results
        ],
    }


def _render_text(results: list[CheckResult]) -> str:
    lines: list[str] = []
    for result in results:
        lines.append(f"[{result.status}] {result.id}")
        if result.files:
            lines.append(f"  files: {', '.join(result.files)}")
        for detail in result.details:
            lines.append(f"  - {detail}")

    failed = [result.id for result in results if result.status == "FAIL"]
    lines.append("")
    if failed:
        lines.append(f"Invariant guard FAILED ({len(failed)} checks failed): {', '.join(failed)}")
    else:
        lines.append("Invariant guard passed")

    return "\n".join(lines)


def main() -> None:
    args = _parse_args()
    repo_root = args.repo_root.resolve()

    if args.paths is not None:
        changed_paths = [normalize_path(path) for path in args.paths]
    else:
        changed_paths = load_changed_paths(repo_root, args.base, args.head)

    results = run_invariant_guard(repo_root, changed_paths, args.all)
    failures = [result for result in results if result.status == "FAIL"]

    if args.json:
        print(json.dumps(_payload(results), indent=2))
    else:
        print(_render_text(results))

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
