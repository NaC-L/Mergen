#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


@dataclass(frozen=True)
class CheckCommand:
    id: str
    description: str
    argv: tuple[str, ...]

    @property
    def shell_preview(self) -> str:
        return subprocess.list2cmdline(list(self.argv))


@dataclass(frozen=True)
class BucketSpec:
    name: str
    description: str
    patterns: tuple[re.Pattern[str], ...]
    default_risk: str
    required_check_ids: tuple[str, ...]


_RISK_RANK = {
    "P0": 0,
    "P1": 1,
    "P2": 2,
    "P3": 3,
}


_CHECK_SPECS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "micro_flags",
        "Run microtests with strict flag checks",
        ("python", "test.py", "micro", "--check-flags"),
    ),
    (
        "negative",
        "Run explicit negative contract checks",
        ("python", "test.py", "negative"),
    ),
    (
        "baseline",
        "Run rewrite baseline gate",
        ("python", "test.py", "baseline"),
    ),
    (
        "coverage_full",
        "Run handler coverage collection",
        ("python", "test.py", "coverage", "--full"),
    ),
    (
        "report_json",
        "Emit coverage report JSON",
        ("python", "test.py", "report", "--json"),
    ),
    (
        "configure_iced",
        "Configure iced backend lane",
        ("cmd", "/c", "scripts\\dev\\configure_iced.cmd"),
    ),
    (
        "build_iced",
        "Build iced backend lane",
        ("cmd", "/c", "scripts\\dev\\build_iced.cmd"),
    ),
    (
        "configure_zydis",
        "Configure zydis backend lane",
        ("cmd", "/c", "scripts\\dev\\configure_zydis.cmd"),
    ),
    (
        "build_zydis",
        "Build zydis backend lane",
        ("cmd", "/c", "scripts\\dev\\build_zydis.cmd"),
    ),
    (
        "review_py_compile",
        "Compile review automation scripts",
        (
            "python",
            "-m",
            "compileall",
            "scripts/review",
        ),
    ),
)


_BUCKET_SPECS: tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "build_and_scope",
        "CMake/backend selection, dev scripts, and scope docs",
        "P1",
        ("configure_iced", "build_iced", "configure_zydis", "build_zydis"),
        (
            r"^cmake/",
            r"^scripts/dev/",
            r"^docs/SCOPE\.md$",
            r"^\.github/workflows/",
        ),
    ),
    (
        "rewrite_ops_baseline",
        "Rewrite gate orchestration, baseline docs, and test runner",
        "P1",
        ("negative", "baseline"),
        (
            r"^docs/REWRITE_BASELINE\.md$",
            r"^scripts/rewrite/(run\.ps1|verify\.ps1|manifest_validation\.ps1)$",
            r"^test\.py$",
        ),
    ),
    (
        "core_orchestration",
        "Lifter entrypoint/stage/pipeline orchestration",
        "P1",
        ("micro_flags",),
        (
            r"^lifter/core/(Lifter\.cpp|LifterApplication\.hpp|LifterStages\.hpp|MergenPB\.hpp|FunctionSignatures\.hpp)$",
        ),
    ),
    (
        "runtime_context_utils",
        "Runtime image mapping, utility helpers, and concolic register model",
        "P1",
        ("micro_flags",),
        (
            r"^lifter/core/(RuntimeImageContext\.hpp|Utils\.cpp|Utils\.h|LifterClass\.hpp|LifterClass_Concolic\.hpp)$",
        ),
    ),
    (
        "disasm_operand_types",
        "Operand type plumbing across Rust/C++ disassembler layers",
        "P1",
        ("micro_flags",),
        (
            r"^icpped_rust/src/lib\.rs$",
            r"^lifter/disasm/",
            r"^lifter/semantics/OperandUtils\.ipp$",
        ),
    ),
    (
        "semantics_and_tests",
        "Opcode/semantics handlers and in-process lifter tests",
        "P1",
        ("micro_flags",),
        (
            r"^lifter/semantics/(?!OperandUtils\.ipp).+",
            r"^lifter/test/(TestInstructions\.cpp|Tester\.hpp)$",
        ),
    ),
    (
        "rewrite_generation_python",
        "Oracle/coverage generation Python pipeline",
        "P1",
        ("negative", "baseline"),
        (
            r"^scripts/rewrite/(generate_oracle_vectors\.py|sleigh_oracle\.py)$",
        ),
    ),
    (
        "coverage_pipeline",
        "Opcode coverage plumbing and coverage/report scripts",
        "P1",
        ("coverage_full", "report_json"),
        (
            r"^lifter/semantics/x86_64_opcodes\.x$",
            r"^scripts/rewrite/(collect_instruction_tests\.py|report_coverage\.py)$",
        ),
    ),
    (
        "vector_artifacts",
        "Oracle vectors, microtest manifests, and golden hashes",
        "P1",
        ("coverage_full", "report_json"),
        (
            r"^lifter/test/test_vectors/",
            r"^scripts/rewrite/(instruction_microtests\.json|oracle_seed_vectors\.json)$",
        ),
    ),
    (
        "review_tooling",
        "Review automation and PR sharding scripts",
        "P2",
        ("review_py_compile",),
        (
            r"^scripts/review/",
        ),
    ),
    (
        "docs_general",
        "Documentation-only changes outside scoped buckets",
        "P3",
        tuple(),
        (
            r"^docs/.+\.md$",
        ),
    ),
)


CHECKS: tuple[CheckCommand, ...] = tuple(
    CheckCommand(id=check_id, description=description, argv=argv)
    for check_id, description, argv in _CHECK_SPECS
)
CHECKS_BY_ID = {check.id: check for check in CHECKS}

BUCKETS: tuple[BucketSpec, ...] = tuple(
    BucketSpec(
        name=name,
        description=description,
        patterns=tuple(re.compile(spec) for spec in patterns),
        default_risk=default_risk,
        required_check_ids=required_check_ids,
    )
    for name, description, default_risk, required_check_ids, patterns in _BUCKET_SPECS
)
BUCKETS_BY_NAME = {bucket.name: bucket for bucket in BUCKETS}


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def load_changed_paths(repo_root: Path, base: str, head: str) -> list[str]:
    cmd = [
        "git",
        "diff",
        "--name-status",
        "--no-color",
        f"{base}...{head}",
    ]
    result = subprocess.run(
        cmd,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")

    paths: list[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        paths.append(normalize_path(parts[-1]))
    return paths


def bucket_for_path(path: str) -> str:
    normalized = normalize_path(path)
    for bucket in BUCKETS:
        if any(pattern.search(normalized) for pattern in bucket.patterns):
            return bucket.name
    return "unassigned"


def bucket_paths(paths: Iterable[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for raw in paths:
        path = normalize_path(raw)
        grouped.setdefault(bucket_for_path(path), []).append(path)

    deduped: dict[str, list[str]] = {}
    for bucket, entries in grouped.items():
        deduped[bucket] = sorted(set(entries))
    return deduped


def chunk_paths(items: Sequence[str], max_size: int) -> list[list[str]]:
    if max_size <= 0:
        return [list(items)]
    return [list(items[idx : idx + max_size]) for idx in range(0, len(items), max_size)]


def bucket_description(bucket_name: str) -> str:
    bucket = BUCKETS_BY_NAME.get(bucket_name)
    if bucket:
        return bucket.description
    return "Paths that did not match predefined review buckets"


def bucket_required_checks(bucket_name: str) -> tuple[CheckCommand, ...]:
    bucket = BUCKETS_BY_NAME.get(bucket_name)
    if not bucket:
        return tuple()

    checks: list[CheckCommand] = []
    for check_id in bucket.required_check_ids:
        check = CHECKS_BY_ID.get(check_id)
        if check:
            checks.append(check)
    return tuple(checks)


def _all_docs(paths: Sequence[str]) -> bool:
    return bool(paths) and all(path.lower().endswith(".md") for path in paths)


def bucket_risk(bucket_name: str, files: Sequence[str]) -> str:
    if bucket_name == "unassigned":
        return "P2"

    bucket = BUCKETS_BY_NAME.get(bucket_name)
    if not bucket:
        return "P2"

    if _all_docs(files):
        return "P3"

    return bucket.default_risk


def risk_rank(risk: str) -> int:
    return _RISK_RANK.get(risk, 99)


def highest_risk(risks: Iterable[str]) -> str:
    known = [risk for risk in risks if risk in _RISK_RANK]
    if not known:
        return "P3"
    return min(known, key=risk_rank)


def required_checks_for_buckets(bucket_names: Sequence[str]) -> list[CheckCommand]:
    ordered_checks: list[CheckCommand] = []
    seen: set[str] = set()

    for bucket_name in bucket_names:
        for check in bucket_required_checks(bucket_name):
            if check.id in seen:
                continue
            seen.add(check.id)
            ordered_checks.append(check)

    return ordered_checks


def bucket_order(bucket_names: Iterable[str]) -> list[str]:
    names = set(bucket_names)
    ordered = [bucket.name for bucket in BUCKETS if bucket.name in names]
    if "unassigned" in names:
        ordered.append("unassigned")
    return ordered
