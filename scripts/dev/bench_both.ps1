$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$rewriteDir = Join-Path $repo 'scripts\rewrite'

$icedLifter = Join-Path $repo 'build_iced\lifter.exe'
$zydisLifter = Join-Path $repo 'build_zydis\lifter.exe'
$icedMicro = Join-Path $repo 'build_iced\rewrite_microtests.exe'
$zydisMicro = Join-Path $repo 'build_zydis\rewrite_microtests.exe'

foreach ($p in @($icedLifter, $zydisLifter, $icedMicro, $zydisMicro)) {
    if (!(Test-Path $p)) { throw "Missing: $p -- build both variants first" }
}

$iterations = 10
$icedMicroTimes = @()
$zydisMicroTimes = @()
$icedBaselineTimes = @()
$zydisBaselineTimes = @()

for ($i = 1; $i -le $iterations; $i++) {
    Write-Host "`n===== Iteration $i / $iterations ====="

    # --- microtests ---
    $im = Measure-Command { & $icedMicro 2>&1 | Out-Null }
    $icedMicroTimes += $im.TotalSeconds

    $zm = Measure-Command { & $zydisMicro 2>&1 | Out-Null }
    $zydisMicroTimes += $zm.TotalSeconds

    # --- baseline ---
    $ib = Measure-Command {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $rewriteDir 'run.ps1') -LifterPath $icedLifter 2>&1 | Out-Null
    }
    $icedBaselineTimes += $ib.TotalSeconds

    $zb = Measure-Command {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $rewriteDir 'run.ps1') -LifterPath $zydisLifter 2>&1 | Out-Null
    }
    $zydisBaselineTimes += $zb.TotalSeconds

    Write-Host ("  ICED  micro={0:F3}s  baseline={1:F2}s" -f $im.TotalSeconds, $ib.TotalSeconds)
    Write-Host ("  ZYDIS micro={0:F3}s  baseline={1:F2}s" -f $zm.TotalSeconds, $zb.TotalSeconds)
}

function Avg([double[]]$a) { ($a | Measure-Object -Average).Average }
function Min([double[]]$a) { ($a | Measure-Object -Minimum).Minimum }
function Max([double[]]$a) { ($a | Measure-Object -Maximum).Maximum }

$iMicroAvg = Avg $icedMicroTimes
$zMicroAvg = Avg $zydisMicroTimes
$iBaseAvg  = Avg $icedBaselineTimes
$zBaseAvg  = Avg $zydisBaselineTimes

Write-Host "`n========== RESULTS ($iterations iterations) =========="
Write-Host ("")
Write-Host ("  Microtests (avg):")
Write-Host ("    ICED  : {0:F3}s  (min={1:F3} max={2:F3})" -f $iMicroAvg, (Min $icedMicroTimes), (Max $icedMicroTimes))
Write-Host ("    ZYDIS : {0:F3}s  (min={1:F3} max={2:F3})" -f $zMicroAvg, (Min $zydisMicroTimes), (Max $zydisMicroTimes))
Write-Host ("    delta : {0:+0.000;-0.000}s" -f ($zMicroAvg - $iMicroAvg))
Write-Host ("")
Write-Host ("  Baseline (avg):")
Write-Host ("    ICED  : {0:F2}s  (min={1:F2} max={2:F2})" -f $iBaseAvg, (Min $icedBaselineTimes), (Max $icedBaselineTimes))
Write-Host ("    ZYDIS : {0:F2}s  (min={1:F2} max={2:F2})" -f $zBaseAvg, (Min $zydisBaselineTimes), (Max $zydisBaselineTimes))
Write-Host ("    delta : {0:+0.00;-0.00}s" -f ($zBaseAvg - $iBaseAvg))
Write-Host ("")
$iTotalAvg = $iMicroAvg + $iBaseAvg
$zTotalAvg = $zMicroAvg + $zBaseAvg
Write-Host ("  Total (avg):")
Write-Host ("    ICED  : {0:F2}s" -f $iTotalAvg)
Write-Host ("    ZYDIS : {0:F2}s" -f $zTotalAvg)
Write-Host ("    delta : {0:+0.00;-0.00}s ({1:+0.0;-0.0}%)" -f ($zTotalAvg - $iTotalAvg), ((($zTotalAvg - $iTotalAvg) / $iTotalAvg) * 100))
