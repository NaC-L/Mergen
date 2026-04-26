param(
    [string]$WorkDir = $(Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'rewrite-regression-work'),
    [string]$ManifestPath = $(Join-Path $PSScriptRoot 'instruction_microtests.json')
)

$ErrorActionPreference = 'Stop'
$irDir = Join-Path $WorkDir 'ir_outputs'

. (Join-Path $PSScriptRoot 'manifest_validation.ps1')

$checks = Get-ValidatedRewriteManifestSamples -ManifestPath $ManifestPath -RequirePatterns

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
    if ($env:CI -and $check.PSObject.Properties['ci_skip'] -and $check.ci_skip) {
        Write-Host "SKIP: $($check.name) (ci_skip: toolchain-dependent)"
        continue
    }

    if ($check.patterns -is [string]) {
        Write-Host "FAIL: $($check.name) patterns must be an array; got string"
        $failed = $true
        continue
    }

    $patterns = @($check.patterns)
    if ($patterns.Count -eq 0) {
        Write-Host "FAIL: $($check.name) has no expected patterns in manifest; add patterns or mark sample as skip"
        $failed = $true
        continue
    }

    $file = Join-Path $irDir "$($check.name).ll"
    if (-not (Test-Path $file)) {
        Write-Host "FAIL: missing $file"
        $failed = $true
        continue
    }

    $lines = Get-Content $file

    foreach ($pattern in $patterns) {
        if ($pattern -is [string]) {
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                Write-Host "FAIL: $($check.name) contains an empty string pattern descriptor"
                $failed = $true
                continue
            }

            if ($lines | Select-String -SimpleMatch -Pattern $pattern -Quiet) {
                Write-Host "PASS: $($check.name) contains '$pattern'"
            }
            else {
                Write-Host "FAIL: $($check.name) missing '$pattern'"
                $failed = $true
            }
            continue
        }

        if ($pattern -is [psobject] -and $pattern.PSObject.Properties['line_all']) {
            if ($pattern.line_all -is [string]) {
                Write-Host "FAIL: $($check.name) line_all descriptor must be an array of tokens"
                $failed = $true
                continue
            }

            $tokens = @($pattern.line_all)
            if ($tokens.Count -eq 0) {
                Write-Host "FAIL: $($check.name) line_all descriptor has no tokens"
                $failed = $true
                continue
            }

            $invalidToken = $tokens | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1
            if ($null -ne $invalidToken) {
                Write-Host "FAIL: $($check.name) line_all descriptor contains non-string or empty token"
                $failed = $true
                continue
            }

            $matched = $false
            foreach ($line in $lines) {
                $lineMatches = $true
                foreach ($token in $tokens) {
                    if (-not (Test-LineTokenMatch -Line $line -Token $token)) {
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

        Write-Host "FAIL: $($check.name) has unsupported pattern descriptor; use string or {\"line_all\":[...]}"
        $failed = $true
    }

    if ($check.PSObject.Properties['case_index_required'] -and $check.case_index_required) {
        $caseIndexScript = Join-Path $PSScriptRoot 'check_case_index.py'
        & python $caseIndexScript gate $file
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAIL: $($check.name) case_index_required gate failed"
            $failed = $true
        }
        else {
            Write-Host "PASS: $($check.name) case_index_required gate"
        }
    }
}

if ($failed) {
    exit 1
}

Write-Host 'All rewrite regression checks passed.'
