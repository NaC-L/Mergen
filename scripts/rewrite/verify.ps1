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

    $lines = Get-Content $file

    foreach ($pattern in @($check.patterns)) {
        if ($pattern -is [string]) {
            if ($lines | Select-String -SimpleMatch -Pattern $pattern -Quiet) {
                Write-Host "PASS: $($check.name) contains '$pattern'"
            }
            else {
                Write-Host "FAIL: $($check.name) missing '$pattern'"
                $failed = $true
            }
            continue
        }

        if ($pattern.PSObject.Properties['line_all']) {
            $tokens = @($pattern.line_all)
            $matched = $false
            foreach ($line in $lines) {
                $lineMatches = $true
                foreach ($token in $tokens) {
                    if ($line.IndexOf([string]$token, [System.StringComparison]::Ordinal) -lt 0) {
                        $lineMatches = $false
                        break
                    }
                }
                if ($lineMatches) {
                    $matched = $true
                    break
                }
            }

            $tokenSummary = ($tokens | ForEach-Object { "'$_'" }) -join " + "
            if ($matched) {
                Write-Host "PASS: $($check.name) line contains $tokenSummary"
            }
            else {
                Write-Host "FAIL: $($check.name) missing line containing $tokenSummary"
                $failed = $true
            }
            continue
        }

        throw "Unsupported pattern descriptor in $ManifestPath for '$($check.name)'"
    }
}

if ($failed) {
    exit 1
}

Write-Host 'All rewrite regression checks passed.'
