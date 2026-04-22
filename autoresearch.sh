#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

cmd.exe /c "scripts\\dev\\build_iced.cmd" > autoresearch-build.log
cmd.exe /c "set MERGEN_DIAG_LIFT_PROGRESS=1&& build_iced\\lifter.exe ..\\testthemida\\example2-virt.bin 0x140001000 > autoresearch-run.log 2>&1"

METRIC_OUTPUT="$(cmd.exe /c py -3 - <<'PY'
import json
from pathlib import Path

path = Path('output_diagnostics.json')
if not path.exists():
    raise SystemExit('output_diagnostics.json was not produced')

with path.open('r', encoding='utf-8') as f:
    data = json.load(f)

summary = data.get('summary', {})
lift = data.get('lift_stats', {})
profile_total = data.get('total_ms')

warnings = int(summary.get('warning', 0))
errors = int(summary.get('error', 0))
unsupported = int(lift.get('instructions_unsupported', 0))
if warnings != 0:
    raise SystemExit(f'warning count regressed: {warnings}')
if errors != 0:
    raise SystemExit(f'error count regressed: {errors}')
if unsupported != 0:
    raise SystemExit(f'unsupported instructions regressed: {unsupported}')

metrics = {
    'instructions_lifted': lift.get('instructions_lifted'),
    'blocks_attempted': lift.get('blocks_attempted'),
    'blocks_completed': lift.get('blocks_completed'),
    'total_ms': profile_total,
}

missing = [name for name, value in metrics.items() if value is None]
if missing:
    raise SystemExit(f'missing metrics: {", ".join(missing)}')

for name, value in metrics.items():
    print(f'METRIC {name}={value}')
PY
 )"
printf '%s\n' "$METRIC_OUTPUT"
