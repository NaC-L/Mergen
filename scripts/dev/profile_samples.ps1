$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$work = Join-Path (Split-Path -Parent $repo) 'rewrite-regression-work'
$lifter = Join-Path $repo 'build_zydis\lifter.exe'
$samples = @(
  @{ name = 'calc_jumptable_large'; exe = 'calc_jumptable_large.exe'; addr = '0x140001000' },
  @{ name = 'calc_switch'; exe = 'calc_switch.exe'; addr = '0x140001000' },
  @{ name = 'jumptable_dense'; exe = 'jumptable_dense.exe'; addr = '0x140001000' }
)
foreach ($sample in $samples) {
  Write-Host "=== $($sample.name) ==="
  & $lifter (Join-Path $work $sample.exe) $sample.addr | Out-Null
  Get-Content (Join-Path $repo 'output_diagnostics.json')
  Write-Host ""
}
