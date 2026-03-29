param(
    [string]$WorkDir = $(Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'rewrite-regression-work'),
    [string]$LifterPath = $(Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build_iced/lifter.exe'),
    [string]$ManifestPath = $(Join-Path $PSScriptRoot 'instruction_microtests.json')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'manifest_validation.ps1')

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildScript = Join-Path $PSScriptRoot 'build_samples.cmd'
$verifyScript = Join-Path $PSScriptRoot 'verify.ps1'

& cmd.exe /c "`"$buildScript`" `"$WorkDir`""
if ($LASTEXITCODE -ne 0) {
    throw "Sample build failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path $LifterPath)) {
    throw "Lifter not found at $LifterPath"
}

$samples = Get-ValidatedRewriteManifestSamples -ManifestPath $ManifestPath -RequireSymbol
$srcDir = Join-Path $repoRoot 'testcases/rewrite_smoke'
$srcNames = @(
    (Get-ChildItem -Path $srcDir -Filter '*.asm' | ForEach-Object { $_.BaseName }) +
    (Get-ChildItem -Path $srcDir -Filter '*.c'   | ForEach-Object { $_.BaseName }) +
    (Get-ChildItem -Path $srcDir -Filter '*.cpp' | ForEach-Object { $_.BaseName })
)
$sampleNames = @($samples | ForEach-Object { $_.name })
$duplicateSrcNames = @(
    $srcNames |
    Group-Object |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object { $_.Name }
)
if ($duplicateSrcNames.Count -gt 0) {
    throw "rewrite_smoke contains duplicate sample base names: $($duplicateSrcNames -join ', ')"
}

$duplicateManifestNames = @(
    $sampleNames |
    Group-Object |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object { $_.Name }
)
if ($duplicateManifestNames.Count -gt 0) {
    throw "Manifest contains duplicate sample names: $($duplicateManifestNames -join ', ')"
}

$missing = @($srcNames | Where-Object { $_ -notin $sampleNames })
if ($missing.Count -gt 0) {
    throw "Manifest is missing rewrite_smoke samples: $($missing -join ', ')"
}

$extra = @($sampleNames | Where-Object { $_ -notin $srcNames })
if ($extra.Count -gt 0) {
    throw "Manifest contains non-existent rewrite_smoke samples: $($extra -join ', ')"
}

$irDir = Join-Path $WorkDir 'ir_outputs'
New-Item -ItemType Directory -Path $irDir -Force | Out-Null
Get-ChildItem -Path $irDir -Filter '*.ll' -File -ErrorAction SilentlyContinue | Remove-Item -Force

$outputLl = Join-Path $repoRoot 'output.ll'
$outputNoOptsLl = Join-Path $repoRoot 'output_no_opts.ll'

Push-Location $repoRoot
try {
    foreach ($sample in $samples) {
        if ($sample.PSObject.Properties['skip'] -and $sample.skip) {
            Write-Host "SKIP: $($sample.name) (known limitation)"
            continue
        }
        # ci_skip: sample depends on toolchain-specific codegen (e.g. STL layout)
        # and cannot be reliably lifted on CI where the compiler version differs.
        if ($env:CI -and $sample.PSObject.Properties['ci_skip'] -and $sample.ci_skip) {
            Write-Host "SKIP: $($sample.name) (ci_skip: toolchain-dependent)"
            continue
        }

        $mapPath = Join-Path $WorkDir "$($sample.name).map"
        if (-not (Test-Path $mapPath)) {
            throw "Map file not found: $mapPath"
        }

        $binaryPath = Join-Path $WorkDir "$($sample.name).exe"
        if (-not (Test-Path $binaryPath)) {
            throw "Binary file not found: $binaryPath"
        }

        $escapedSymbol = [System.Text.RegularExpressions.Regex]::Escape($sample.symbol)
        $symbolRegex = "^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+$escapedSymbol\s+([0-9A-Fa-f]{8,16})\b"
        $symbolLine = Get-Content $mapPath | Where-Object { $_ -match $symbolRegex } | Select-Object -First 1
        if (-not $symbolLine) {
            throw "Symbol $($sample.symbol) not found in $mapPath"
        }

        $match = [System.Text.RegularExpressions.Regex]::Match(
            $symbolLine,
            $symbolRegex,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $match.Success) {
            throw "Could not parse symbol address from line: $symbolLine"
        }

        $targetAddress = "0x$($match.Groups[1].Value)"

        Remove-Item $outputLl -Force -ErrorAction SilentlyContinue
        Remove-Item $outputNoOptsLl -Force -ErrorAction SilentlyContinue

        Write-Host "Lifting $binaryPath @ $targetAddress"
        & $LifterPath $binaryPath $targetAddress
        if ($LASTEXITCODE -ne 0) {
            throw "Lifter failed for $($sample.name)"
        }

        if (-not (Test-Path $outputLl) -or -not (Test-Path $outputNoOptsLl)) {
            throw "Lifter did not emit expected output.ll/output_no_opts.ll for '$($sample.name)'"
        }

        Copy-Item $outputLl (Join-Path $irDir "$($sample.name).ll") -Force
        Copy-Item $outputNoOptsLl (Join-Path $irDir "$($sample.name)_no_opts.ll") -Force
    }
}
finally {
    Pop-Location
}

& $verifyScript -WorkDir $WorkDir -ManifestPath $ManifestPath
if ($LASTEXITCODE -ne 0) {
    throw "Verification failed"
}

Write-Host "Rewrite regression succeeded. IR files: $irDir"
