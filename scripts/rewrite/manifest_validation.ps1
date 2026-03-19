function Test-IsSafeSampleName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    if ($Name -match '[\\/]') {
        return $false
    }

    if ($Name.Contains('..')) {
        return $false
    }

    return $true
}

function Get-ValidatedRewriteManifestSamples {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [switch]$RequireSymbol,

        [switch]$RequirePatterns
    )

    if (-not (Test-Path $ManifestPath)) {
        throw "Manifest not found at $ManifestPath"
    }

    try {
        $manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Manifest at $ManifestPath is not valid JSON: $($_.Exception.Message)"
    }

    if (-not $manifest -or -not $manifest.PSObject.Properties['samples']) {
        throw "Manifest at $ManifestPath must contain a top-level 'samples' field"
    }

    $samplesRaw = @($manifest.samples)
    if ($samplesRaw.Count -eq 0) {
        throw "No samples found in $ManifestPath"
    }

    $samples = @()
    for ($index = 0; $index -lt $samplesRaw.Count; $index++) {
        $sample = $samplesRaw[$index]
        if ($sample -isnot [pscustomobject]) {
            throw "Manifest sample[$index] must be an object"
        }

        if (-not $sample.PSObject.Properties['name'] -or -not ($sample.name -is [string]) -or -not (Test-IsSafeSampleName -Name $sample.name)) {
            throw "Manifest sample[$index] has invalid name '$($sample.name)' (must be a non-empty string without path traversal characters)"
        }

        if ($sample.PSObject.Properties['skip'] -and ($sample.skip -isnot [bool])) {
            throw "Manifest sample '$($sample.name)' has invalid skip value '$($sample.skip)' (must be true or false)"
        }

        if ($RequireSymbol -and (-not $sample.PSObject.Properties['symbol'] -or -not ($sample.symbol -is [string]) -or [string]::IsNullOrWhiteSpace($sample.symbol))) {
            throw "Manifest sample '$($sample.name)' has invalid symbol '$($sample.symbol)' (must be a non-empty string)"
        }

        if ($RequirePatterns -and (-not $sample.PSObject.Properties['patterns'])) {
            throw "Manifest sample '$($sample.name)' is missing required 'patterns' field"
        }

        $samples += $sample
    }

    return $samples
}
