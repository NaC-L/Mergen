#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

tmp_out="$(mktemp)"
trap 'rm -f "$tmp_out"' EXIT

python.exe test.py themida | tee "$tmp_out"

pass_count="$(grep -c '^PASS:' "$tmp_out" || true)"
missing_count="$(grep -c 'MISSING required import' "$tmp_out" || true)"

printf 'METRIC themida_pass_count=%s\n' "$pass_count"
printf 'METRIC missing_required_imports=%s\n' "$missing_count"
