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

function Test-LineTokenMatch {
    param(
        [string]$Line,
        [string]$Token
    )

    if ([string]::IsNullOrEmpty($Token)) {
        return $true
    }

    $first = $Token[0]
    $last = $Token[$Token.Length - 1]
    $startsWithWord = [char]::IsLetterOrDigit($first) -or $first -eq '_'
    $endsWithWord = [char]::IsLetterOrDigit($last) -or $last -eq '_'

    $escaped = [System.Text.RegularExpressions.Regex]::Escape($Token)
    $prefix = if ($startsWithWord) { '(?<![0-9A-Za-z_])' } else { '' }
    $suffix = if ($endsWithWord) { '(?![0-9A-Za-z_])' } else { '' }
    $pattern = "$prefix$escaped$suffix"

    return [System.Text.RegularExpressions.Regex]::IsMatch(
        $Line,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

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
                    if (-not (Test-LineTokenMatch -Line $line -Token ([string]$token))) {
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
