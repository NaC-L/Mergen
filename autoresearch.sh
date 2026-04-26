#!/usr/bin/env bash
# Cheap manifest-stats harness for the VM-sample population task.
#
# Primary metric: number of VM-shaped samples in instruction_microtests.json.
# A "VM-shaped" sample has "vm" (case-insensitive) in `name` and non-empty
# `patterns` and `semantic` lists. This rewards fully-wired samples, not stubs.
#
# Implementation note: run_experiment's bash subshell on Windows often
# does not expose python on PATH, so we go through powershell.exe (always
# present in System32) which then resolves py.exe / python via Get-Command.
# Stdout flushes through the powershell process pipe reliably.
set -euo pipefail

cd "$(dirname "$0")"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
$ErrorActionPreference = "Stop"
$py = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python.exe -ErrorAction SilentlyContinue }
if (-not $py) { Write-Error "no python interpreter on PATH"; exit 127 }

$code = @"
import json
from pathlib import Path
with Path('"'"'scripts/rewrite/instruction_microtests.json'"'"').open('"'"'r'"'"', encoding='"'"'utf-8'"'"') as f:
    data = json.load(f)
samples = data.get('"'"'samples'"'"') or []
vm = 0
ts = 0
for s in samples:
    name = (s.get('"'"'name'"'"') or '"'"''"'"').lower()
    patterns = s.get('"'"'patterns'"'"') or []
    semantic = s.get('"'"'semantic'"'"') or []
    ts += len(semantic)
    if '"'"'vm'"'"' in name and patterns and semantic:
        vm += 1
print(f'"'"'METRIC vm_sample_count={vm}'"'"')
print(f'"'"'METRIC total_semantic_cases={ts}'"'"')
print(f'"'"'METRIC manifest_samples={len(samples)}'"'"')
"@
& $py.Source -c $code
'
