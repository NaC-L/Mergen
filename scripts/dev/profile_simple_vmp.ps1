$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lifter = Join-Path $repo 'build_zydis\lifter.exe'
$diagPath = Join-Path $repo 'output_diagnostics.json'

$targets = @(
  @{ name = 'simple_unprotected'; exe = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen/simple/simple_target.exe'; addr = '0x1400113CA'; timeoutSec = 30 },
  @{ name = 'simple_vmp381_one_vm'; exe = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen/simple/protected381/simple_target_one_vm.vmp38.exe'; addr = '0x1400113CA'; timeoutSec = 60 },
  @{ name = 'simple_vmp381_full'; exe = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen/simple/protected381/simple_target.vmp.exe'; addr = '0x1400113CA'; timeoutSec = 60 },
  @{ name = 'simple_vmp36'; exe = 'C:/Users/Yusuf/Desktop/mergenrewrite/Mergen/simple/protected/simple_target_protected.vmp.exe'; addr = '0x14009E2E1'; timeoutSec = 90 }
)

function Run-Target($target) {
  if (!(Test-Path $target.exe)) {
    return [pscustomobject]@{ Name = $target.name; Status = 'missing'; WallMs = $null; TotalMs = $null; PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null; Optimization = $null; WriteOptIr = $null; Note = 'binary not found' }
  }

  Remove-Item $diagPath -Force -ErrorAction SilentlyContinue

  $job = Start-Job -ScriptBlock {
    param($repoPath, $lifterPath, $exePath, $addr)
    Set-Location $repoPath
    & $lifterPath $exePath $addr | Out-Null
    return $LASTEXITCODE
  } -ArgumentList $repo, $lifter, $target.exe, $target.addr

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $completed = Wait-Job $job -Timeout $target.timeoutSec
  $sw.Stop()

  if ($null -eq $completed) {
    Stop-Job $job | Out-Null
    Remove-Job $job | Out-Null
    return [pscustomobject]@{ Name = $target.name; Status = 'timeout'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null; PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null; Optimization = $null; WriteOptIr = $null; Note = ('timed out after ' + $target.timeoutSec + 's') }
  }

  $exitCode = Receive-Job $job
  Remove-Job $job | Out-Null

  if ($exitCode -ne 0) {
    return [pscustomobject]@{ Name = $target.name; Status = 'failed'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null; PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null; Optimization = $null; WriteOptIr = $null; Note = ('exit code ' + $exitCode) }
  }

  if (!(Test-Path $diagPath)) {
    return [pscustomobject]@{ Name = $target.name; Status = 'no_diagnostics'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null; PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null; Optimization = $null; WriteOptIr = $null; Note = 'missing output_diagnostics.json' }
  }

  $json = Get-Content $diagPath -Raw | ConvertFrom-Json
  return [pscustomobject]@{
    Name = $target.name
    Status = 'ok'
    WallMs = $sw.Elapsed.TotalMilliseconds
    TotalMs = [double]$json.total_ms
    PeSetup = [double]$json.profile.pe_setup
    SignatureSearch = [double]$json.profile.signature_search
    Lift = [double]$json.profile.lift
    WriteUnoptIr = [double]$json.profile.write_unopt_ir
    Optimization = [double]$json.profile.optimization
    WriteOptIr = [double]$json.profile.write_opt_ir
    Note = ''
  }
}

$results = foreach ($target in $targets) {
  Write-Host ('Profiling ' + $target.name + ' @ ' + $target.addr)
  Run-Target $target
}

Write-Host ''
Write-Host '========== SIMPLE TARGET PROFILE =========='
foreach ($r in $results) {
  if ($r.Status -eq 'ok') {
    Write-Host ('{0,-22} wall={1,10:F3} ms total={2,10:F3} ms opt={3,10:F3} ms lift={4,8:F3} ms sig={5,8:F3} ms write_u={6,8:F3} ms write_o={7,8:F3} ms' -f $r.Name, $r.WallMs, $r.TotalMs, $r.Optimization, $r.Lift, $r.SignatureSearch, $r.WriteUnoptIr, $r.WriteOptIr)
  } else {
    Write-Host ('{0,-22} status={1} note={2} wall={3}' -f $r.Name, $r.Status, $r.Note, $r.WallMs)
  }
}
