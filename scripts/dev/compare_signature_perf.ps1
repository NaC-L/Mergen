$ErrorActionPreference = 'Stop'

$cases = @(
  @{ name = 'current'; repo = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen'; lifter = 'build_zydis/lifter.exe' },
  @{ name = 'head'; repo = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen-head'; lifter = 'build_zydis/lifter.exe' }
)

$sampleExe = 'C:/Users/Yusuf/Desktop/mergenrewrite/rewrite-regression-work/calc_switch.exe'
$sampleAddr = '0x140001000'
$iterations = 20

function Avg($values) {
  if ($values.Count -eq 0) { return 0.0 }
  return ($values | Measure-Object -Average).Average
}
function MinVal($values) { return ($values | Measure-Object -Minimum).Minimum }
function MaxVal($values) { return ($values | Measure-Object -Maximum).Maximum }

$results = @()

foreach ($case in $cases) {
  $repo = $case.repo
  $lifter = Join-Path $repo $case.lifter
  $diagPath = Join-Path $repo 'output_diagnostics.json'
  $wallTimes = @()
  $sigTimes = @()
  $totalTimes = @()

  if (!(Test-Path $lifter)) { throw "Missing lifter: $lifter" }

  Write-Host "=== $($case.name) ==="
  for ($i = 1; $i -le $iterations; $i++) {
    $stdout = $null
    $elapsed = Measure-Command {
      $stdout = (& $lifter $sampleExe $sampleAddr | Out-String)
    }

    $sigMs = $null
    $totalMs = $null
    if (Test-Path $diagPath) {
      $json = Get-Content $diagPath -Raw | ConvertFrom-Json
      if ($json.profile -and $json.profile.signature_search -ne $null) {
        $sigMs = [double]$json.profile.signature_search
      }
      if ($json.total_ms -ne $null) {
        $totalMs = [double]$json.total_ms
      }
    }

    if ($sigMs -eq $null -and $stdout -match '([0-9]+(?:\.[0-9]+)?) milliseconds has past') {
      $sigMs = [double]$matches[1]
    }
    if ($totalMs -eq $null -and $stdout -match '([0-9]+(?:\.[0-9]+)?) milliseconds have passed') {
      $totalMs = [double]$matches[1]
    }

    if ($sigMs -eq $null -or $totalMs -eq $null) {
      throw "Could not extract timings for $($case.name) run $i"
    }

    $wallTimes += $elapsed.TotalMilliseconds
    $sigTimes += $sigMs
    $totalTimes += $totalMs
    Write-Host ("  run {0,2}: wall={1,6:F3} ms  sig={2,6:F3} ms  total={3,6:F3} ms" -f $i, $elapsed.TotalMilliseconds, $sigMs, $totalMs)
  }

  $results += [pscustomobject]@{
    Name = $case.name
    WallAvg = Avg $wallTimes
    WallMin = MinVal $wallTimes
    WallMax = MaxVal $wallTimes
    SigAvg = Avg $sigTimes
    SigMin = MinVal $sigTimes
    SigMax = MaxVal $sigTimes
    TotalAvg = Avg $totalTimes
    TotalMin = MinVal $totalTimes
    TotalMax = MaxVal $totalTimes
  }
}

Write-Host ""
Write-Host "========== SUMMARY =========="
foreach ($r in $results) {
  Write-Host ("{0}: wall avg={1:F3} ms [{2:F3}, {3:F3}]  sig avg={4:F3} ms [{5:F3}, {6:F3}]  total avg={7:F3} ms [{8:F3}, {9:F3}]" -f $r.Name, $r.WallAvg, $r.WallMin, $r.WallMax, $r.SigAvg, $r.SigMin, $r.SigMax, $r.TotalAvg, $r.TotalMin, $r.TotalMax)
}

$current = $results | Where-Object Name -eq 'current'
$head = $results | Where-Object Name -eq 'head'
if ($null -ne $current -and $null -ne $head) {
  Write-Host ""
  Write-Host ("delta current-head: wall={0:+0.000;-0.000} ms  sig={1:+0.000;-0.000} ms  total={2:+0.000;-0.000} ms" -f ($current.WallAvg - $head.WallAvg), ($current.SigAvg - $head.SigAvg), ($current.TotalAvg - $head.TotalAvg))
}
