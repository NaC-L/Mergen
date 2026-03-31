$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workDir = Join-Path (Split-Path -Parent $repo) 'rewrite-regression-work'
$lifter = Join-Path $repo 'build_zydis\lifter.exe'
$manifestPath = Join-Path $repo 'scripts\rewrite\instruction_microtests.json'
$diagPath = Join-Path $repo 'output_diagnostics.json'

if (!(Test-Path $lifter)) { throw "Missing lifter: $lifter" }
if (!(Test-Path $manifestPath)) { throw "Missing manifest: $manifestPath" }

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$samples = @($manifest.samples | Where-Object {
  -not ($_.PSObject.Properties['skip'] -and $_.skip) -and
  -not ($_.PSObject.Properties['ci_skip'] -and $_.ci_skip)
})

$rows = @()
$stageTotals = @{}
$profiledSampleCount = 0
$totalMsAll = 0.0

foreach ($sample in $samples) {
  $mapPath = Join-Path $workDir ($sample.name + '.map')
  $binaryPath = Join-Path $workDir ($sample.name + '.exe')
  if (!(Test-Path $mapPath)) { throw "Map file not found: $mapPath" }
  if (!(Test-Path $binaryPath)) { throw "Binary file not found: $binaryPath" }

  $escapedSymbol = [System.Text.RegularExpressions.Regex]::Escape($sample.symbol)
  $symbolRegex = '^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+' + $escapedSymbol + '\s+([0-9A-Fa-f]{8,16})\b'
  $symbolLine = Get-Content $mapPath | Where-Object { $_ -match $symbolRegex } | Select-Object -First 1
  if (-not $symbolLine) { throw "Symbol $($sample.symbol) not found in $mapPath" }

  $match = [System.Text.RegularExpressions.Regex]::Match(
    $symbolLine,
    $symbolRegex,
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
  )
  if (-not $match.Success) { throw "Could not parse symbol address from line: $symbolLine" }

  $targetAddress = '0x' + $match.Groups[1].Value
  Write-Host ("Profiling {0} @ {1}" -f $sample.name, $targetAddress)

  & $lifter $binaryPath $targetAddress | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Lifter failed for $($sample.name)" }
  if (!(Test-Path $diagPath)) { throw "Diagnostics file missing after $($sample.name)" }

  $json = Get-Content $diagPath -Raw | ConvertFrom-Json
  $profile = $json.profile
  $profiledSampleCount += 1
  $totalMsAll += [double]$json.total_ms

  foreach ($prop in $profile.PSObject.Properties) {
    $stageName = $prop.Name
    $stageValue = [double]$prop.Value
    if (-not $stageTotals.ContainsKey($stageName)) {
      $stageTotals[$stageName] = 0.0
    }
    $stageTotals[$stageName] += $stageValue
  }

  $rows += [pscustomobject]@{
    Name = $sample.name
    TotalMs = [double]$json.total_ms
    PeSetup = [double]$profile.pe_setup
    SignatureSearch = [double]$profile.signature_search
    Lift = [double]$profile.lift
    WriteUnoptIr = [double]$profile.write_unopt_ir
    Optimization = [double]$profile.optimization
    WriteOptIr = [double]$profile.write_opt_ir
    BlocksAttempted = [int]$json.lift_stats.blocks_attempted
    InstructionsLifted = [int]$json.lift_stats.instructions_lifted
  }
}

Write-Host ''
Write-Host '========== STAGE TOTALS =========='
$stageTotals.GetEnumerator() |
  Sort-Object Value -Descending |
  ForEach-Object {
    $pct = if ($totalMsAll -gt 0) { ($_.Value / $totalMsAll) * 100.0 } else { 0.0 }
    Write-Host ('{0,-18} {1,8:F3} ms   {2,6:F2}%' -f $_.Key, $_.Value, $pct)
  }

Write-Host ''
Write-Host '========== STAGE AVERAGES =========='
$stageTotals.GetEnumerator() |
  Sort-Object Name |
  ForEach-Object {
    $avg = if ($profiledSampleCount -gt 0) { $_.Value / $profiledSampleCount } else { 0.0 }
    Write-Host ('{0,-18} {1,8:F3} ms/sample' -f $_.Key, $avg)
  }

Write-Host ''
Write-Host '========== SLOWEST SAMPLES BY TOTAL =========='
$rows | Sort-Object TotalMs -Descending | Select-Object -First 10 |
  ForEach-Object {
    Write-Host ('{0,-24} total={1,7:F3}  opt={2,7:F3}  lift={3,7:F3}  sig={4,7:F3}  instr={5,4}' -f $_.Name, $_.TotalMs, $_.Optimization, $_.Lift, $_.SignatureSearch, $_.InstructionsLifted)
  }

Write-Host ''
Write-Host '========== HIGHEST OPTIMIZATION COST =========='
$rows | Sort-Object Optimization -Descending | Select-Object -First 10 |
  ForEach-Object {
    Write-Host ('{0,-24} opt={1,7:F3}  total={2,7:F3}  lift={3,7:F3}  sig={4,7:F3}' -f $_.Name, $_.Optimization, $_.TotalMs, $_.Lift, $_.SignatureSearch)
  }

Write-Host ''
Write-Host '========== HIGHEST LIFT COST =========='
$rows | Sort-Object Lift -Descending | Select-Object -First 10 |
  ForEach-Object {
    Write-Host ('{0,-24} lift={1,7:F3}  total={2,7:F3}  opt={3,7:F3}  sig={4,7:F3}  blocks={5,4}  instr={6,4}' -f $_.Name, $_.Lift, $_.TotalMs, $_.Optimization, $_.SignatureSearch, $_.BlocksAttempted, $_.InstructionsLifted)
  }
