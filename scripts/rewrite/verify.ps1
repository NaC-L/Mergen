param(
    [string]$WorkDir = $(Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'rewrite-regression-work'),
    [string]$ManifestPath = $(Join-Path $PSScriptRoot 'instruction_microtests.json')
)

$ErrorActionPreference = 'Stop'
$irDir = Join-Path $WorkDir 'ir_outputs'

if (-not (Test-Path $ManifestPath)) {
    throw "Manifest not found at $ManifestPath"
}

$manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$checks = @($manifest.samples)
if ($checks.Count -eq 0) {
    throw "No checks found in $ManifestPath"
}

$failed = $false

foreach ($check in $checks) {
    if ($check.PSObject.Properties['skip'] -and $check.skip) {
        Write-Host "SKIP: $($check.name) (known limitation)"
        continue
    }
    $file = Join-Path $irDir "$($check.name).ll"
    if (-not (Test-Path $file)) {
        Write-Host "FAIL: missing $file"
        $failed = $true
        continue
    }

    foreach ($pattern in @($check.patterns)) {
        if (Select-String -Path $file -SimpleMatch -Pattern $pattern -Quiet) {
            Write-Host "PASS: $($check.name) contains '$pattern'"
        }
        else {
            Write-Host "FAIL: $($check.name) missing '$pattern'"
            $failed = $true
        }
    }
}

if ($failed) {
    exit 1
}

Write-Host 'All rewrite regression checks passed.'
