param(
  [string]$LifterPath = '',
  [string[]]$Filter = @(),
  [switch]$Validate
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$simpleDir = Join-Path $repo 'simple'
$diagPath = Join-Path $repo 'output_diagnostics.json'
$outputLl = Join-Path $repo 'output.ll'
$outputNoOptsLl = Join-Path $repo 'output_no_opts.ll'

function Resolve-LifterPath {
  param([string]$Candidate)

  if ($Candidate) {
    if (!(Test-Path $Candidate)) {
      throw "Lifter not found at '$Candidate'"
    }
    return $Candidate
  }

  $preferred = @(
    (Join-Path $repo 'build_iced\lifter.exe'),
    (Join-Path $repo 'build_zydis\lifter.exe')
  )

  foreach ($path in $preferred) {
    if (Test-Path $path) {
      return $path
    }
  }

  throw "No lifter build found. Expected build_iced\\lifter.exe or build_zydis\\lifter.exe"
}

$lifter = Resolve-LifterPath $LifterPath

$targets = @(
  @{ name = 'simple_unprotected'; exe = (Join-Path $simpleDir 'simple_target.exe'); addr = '0x1400113CA'; timeoutSec = 30; required = $false },
  @{ name = 'simple_vmp381_one_vm'; exe = (Join-Path $simpleDir 'protected381\simple_target_one_vm.vmp38.exe'); addr = '0x1400113CA'; timeoutSec = 60; required = $true },
  @{ name = 'simple_vmp381_full'; exe = (Join-Path $simpleDir 'protected381\simple_target.vmp.exe'); addr = '0x1400113CA'; timeoutSec = 60; required = $true },
  @{ name = 'simple_vmp36'; exe = (Join-Path $simpleDir 'protected\simple_target_protected.vmp.exe'); addr = '0x14009E2E1'; timeoutSec = 90; required = $false }
)

if ($Filter.Count -gt 0) {
  $targets = @(
    $targets | Where-Object {
      $target = $_
      ($Filter | Where-Object { $target.name -like ('*' + $_ + '*') }).Count -gt 0
    }
  )
}

if ($targets.Count -eq 0) {
  throw 'No VMP targets matched the requested filter.'
}

if ($Validate -and (@($targets | Where-Object { $_.required })).Count -eq 0) {
  throw 'Validation requires at least one required VMP 3.8.x target in the filtered target set.'
}


function Run-Target($target) {
  if (!(Test-Path $target.exe)) {
    return [pscustomobject]@{
      Name = $target.name; Required = [bool]$target.required; Status = 'missing'; WallMs = $null; TotalMs = $null
      PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null
      Optimization = $null; WriteOptIr = $null; Errors = $null; Warnings = $null
      BlocksAttempted = $null; BlocksCompleted = $null; Note = 'binary not found'
    }
  }

  Remove-Item $diagPath, $outputLl, $outputNoOptsLl -Force -ErrorAction SilentlyContinue

  $job = Start-Job -ScriptBlock {
    param($repoPath, $lifterPath, $exePath, $addr)
    Set-Location $repoPath
    & $lifterPath $exePath $addr *> $null
    return $LASTEXITCODE
  } -ArgumentList $repo, $lifter, $target.exe, $target.addr

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $completed = Wait-Job $job -Timeout $target.timeoutSec
  $sw.Stop()

  if ($null -eq $completed) {
    Stop-Job $job | Out-Null
    Remove-Job $job | Out-Null
    return [pscustomobject]@{
      Name = $target.name; Required = [bool]$target.required; Status = 'timeout'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null
      PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null
      Optimization = $null; WriteOptIr = $null; Errors = $null; Warnings = $null
      BlocksAttempted = $null; BlocksCompleted = $null; Note = ('timed out after ' + $target.timeoutSec + 's')
    }
  }

  $exitCode = Receive-Job $job
  Remove-Job $job | Out-Null

  if ($exitCode -ne 0) {
    return [pscustomobject]@{
      Name = $target.name; Required = [bool]$target.required; Status = 'failed'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null
      PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null
      Optimization = $null; WriteOptIr = $null; Errors = $null; Warnings = $null
      BlocksAttempted = $null; BlocksCompleted = $null; Note = ('exit code ' + $exitCode)
    }
  }

  if (!(Test-Path $diagPath) -or !(Test-Path $outputLl) -or !(Test-Path $outputNoOptsLl)) {
    return [pscustomobject]@{
      Name = $target.name; Required = [bool]$target.required; Status = 'missing_output'; WallMs = $sw.Elapsed.TotalMilliseconds; TotalMs = $null
      PeSetup = $null; SignatureSearch = $null; Lift = $null; WriteUnoptIr = $null
      Optimization = $null; WriteOptIr = $null; Errors = $null; Warnings = $null
      BlocksAttempted = $null; BlocksCompleted = $null; Note = 'missing output_diagnostics.json/output.ll/output_no_opts.ll'
    }
  }

  $json = Get-Content $diagPath -Raw | ConvertFrom-Json
  $errorCount = 0
  $warningCount = 0
  if ($json.summary) {
    $errorCount = [int]$json.summary.error
    $warningCount = [int]$json.summary.warning
  }

  $note = ''
  if ($json.lift_stats.blocks_completed -eq 0) {
    $note = '0 completed blocks; inspect output.ll before trusting result'
  }

  return [pscustomobject]@{
    Name = $target.name
    Required = [bool]$target.required
    Status = 'ok'
    WallMs = $sw.Elapsed.TotalMilliseconds
    TotalMs = [double]$json.total_ms
    PeSetup = [double]$json.profile.pe_setup
    SignatureSearch = [double]$json.profile.signature_search
    Lift = [double]$json.profile.lift
    WriteUnoptIr = [double]$json.profile.write_unopt_ir
    Optimization = [double]$json.profile.optimization
    WriteOptIr = [double]$json.profile.write_opt_ir
    Errors = $errorCount
    Warnings = $warningCount
    BlocksAttempted = [int]$json.lift_stats.blocks_attempted
    BlocksCompleted = [int]$json.lift_stats.blocks_completed
    Note = $note
  }
}

$results = foreach ($target in $targets) {
  Write-Host ('Profiling ' + $target.name + ' @ ' + $target.addr)
  Run-Target $target
}

Write-Host ''
Write-Host '========== SIMPLE TARGET PROFILE =========='
foreach ($r in $results) {
  $tier = if ($r.Required) { 'gate' } else { 'best-effort' }
  if ($r.Status -eq 'ok') {
    $noteSuffix = ''
    if ($r.Note) {
      $noteSuffix = (' note=' + $r.Note)
    }
    Write-Host ('{0,-22} tier={1,-11} wall={2,10:F3} ms total={3,10:F3} ms opt={4,10:F3} ms lift={5,8:F3} ms sig={6,8:F3} ms write_u={7,8:F3} ms write_o={8,8:F3} ms errs={9} warns={10} blocks={11}/{12}{13}' -f $r.Name, $tier, $r.WallMs, $r.TotalMs, $r.Optimization, $r.Lift, $r.SignatureSearch, $r.WriteUnoptIr, $r.WriteOptIr, $r.Errors, $r.Warnings, $r.BlocksCompleted, $r.BlocksAttempted, $noteSuffix)
  } else {
    Write-Host ('{0,-22} tier={1,-11} status={2} note={3} wall={4}' -f $r.Name, $tier, $r.Status, $r.Note, $r.WallMs)
  }
}

if ($Validate) {
  $hasHardRegression = {
    param($result)
    return $result.Status -ne 'ok' -or $result.Errors -gt 0 -or
      ($result.Status -eq 'ok' -and $result.BlocksCompleted -le 0)
  }
  $failures = @(
    $results | Where-Object { $_.Required -and (& $hasHardRegression $_) }
  )
  $bestEffortIssues = @(
    $results | Where-Object { -not $_.Required -and (& $hasHardRegression $_) }
  )
  if ($bestEffortIssues.Count -gt 0) {
    Write-Host ''
    Write-Host 'Best-effort VMP targets with issues:'
    foreach ($issue in $bestEffortIssues) {
      Write-Host ('- {0}: status={1} errors={2} note={3}' -f $issue.Name, $issue.Status, $issue.Errors, $issue.Note)
    }
  }
  if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'VMP validation failed for required targets:'
    foreach ($failure in $failures) {
      Write-Host ('- {0}: status={1} errors={2} note={3}' -f $failure.Name, $failure.Status, $failure.Errors, $failure.Note)
    }
    exit 1
  }

  Write-Host ''
  Write-Host ('VMP validation passed for {0} required target(s).' -f (@($results | Where-Object { $_.Required })).Count)
}
