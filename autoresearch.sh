#!/usr/bin/env bash
# Cheap manifest-stats harness for the VM-sample population task.
#
# Primary metric: number of VM-shaped samples in instruction_microtests.json.
# A "VM-shaped" sample has "vm" (case-insensitive) in `name` and non-empty
# `patterns` and `semantic` lists. This rewards fully-wired samples, not stubs.
set -euo pipefail

cd "$(dirname "$0")"

# Generate metrics via PowerShell: natively on PATH, no stdout plumbing issues
# when run under bash on Windows.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
  \$ErrorActionPreference = 'Stop';
  \$raw = Get-Content -Raw -LiteralPath 'scripts/rewrite/instruction_microtests.json';
  \$data = \$raw | ConvertFrom-Json;
  \$samples = @(\$data.samples);
  \$vm = 0;
  \$totalSem = 0;
  foreach (\$s in \$samples) {
    \$name = ''; if (\$s.name) { \$name = [string]\$s.name };
    \$patterns = @(); if (\$s.patterns) { \$patterns = @(\$s.patterns) };
    \$semantic = @(); if (\$s.semantic) { \$semantic = @(\$s.semantic) };
    \$totalSem += \$semantic.Count;
    if (\$name.ToLower().Contains('vm') -and \$patterns.Count -gt 0 -and \$semantic.Count -gt 0) {
      \$vm += 1;
    }
  };
  Write-Output (\"METRIC vm_sample_count=\$vm\");
  Write-Output (\"METRIC total_semantic_cases=\$totalSem\");
  Write-Output (\"METRIC manifest_samples=\$(\$samples.Count)\");
"
