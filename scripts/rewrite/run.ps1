param(
    [string]$WorkDir = $(Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'rewrite-regression-work'),
    [string]$LifterPath = $(Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build_iced/lifter.exe'),
    [string]$ManifestPath = $(Join-Path $PSScriptRoot 'instruction_microtests.json')
)

$ErrorActionPreference = 'Stop'

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

if (-not (Test-Path $ManifestPath)) {
    throw "Manifest not found at $ManifestPath"
}

$manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$samples = @($manifest.samples)
if ($samples.Count -eq 0) {
    throw "No samples found in $ManifestPath"
}

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

Push-Location $repoRoot
try {
    foreach ($sample in $samples) {
        if ($sample.PSObject.Properties['skip'] -and $sample.skip) {
            Write-Host "SKIP: $($sample.name) (known limitation)"
            continue
        }

        $mapPath = Join-Path $WorkDir "$($sample.name).map"
        if (-not (Test-Path $mapPath)) {
            throw "Map file not found: $mapPath"
        }

        $symbolLine = Get-Content $mapPath | Where-Object { $_ -match "\s$($sample.symbol)\s" } | Select-Object -First 1
        if (-not $symbolLine) {
            throw "Symbol $($sample.symbol) not found in $mapPath"
        }

        $tokens = ($symbolLine -split '\s+') | Where-Object { $_ -ne '' }
        if ($tokens.Count -lt 3) {
            throw "Could not parse symbol line: $symbolLine"
        }

        $targetAddress = "0x$($tokens[2])"
        $binaryPath = Join-Path $WorkDir "$($sample.name).exe"

        Write-Host "Lifting $binaryPath @ $targetAddress"
        & $LifterPath $binaryPath $targetAddress
        if ($LASTEXITCODE -ne 0) {
            throw "Lifter failed for $($sample.name)"
        }

        Copy-Item (Join-Path $repoRoot 'output.ll') (Join-Path $irDir "$($sample.name).ll") -Force
        Copy-Item (Join-Path $repoRoot 'output_no_opts.ll') (Join-Path $irDir "$($sample.name)_no_opts.ll") -Force
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
