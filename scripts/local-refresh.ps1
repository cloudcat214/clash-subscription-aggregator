param(
    [int]$MaxNodes = 150,
    [int]$Rounds = 3,
    [double]$Timeout = 5,
    [int]$Concurrency = 6,
    [ValidateSet("stable", "verified", "fast")]
    [string]$MinVerdict = "stable",
    [string]$Core
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($Core)) {
    foreach ($Candidate in @(
        "D:\Program Files\Clash Verge\verge-mihomo.exe",
        "C:\Program Files\Clash Verge\verge-mihomo.exe"
    )) {
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $Core = $Candidate
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($Core) -or -not (Test-Path -LiteralPath $Core -PathType Leaf)) {
    throw "找不到 verge-mihomo.exe。请使用 -Core 指定 Mihomo 可执行文件路径。"
}

Push-Location $ProjectRoot
try {
    & python -m aggregator run `
        --config config/sources.yaml `
        --output dist-local `
        --state state-local `
        --no-private `
        --mihomo $Core `
        --probe `
        --probe-max-nodes $MaxNodes `
        --probe-rounds $Rounds `
        --probe-timeout $Timeout `
        --probe-concurrency $Concurrency `
        --probe-min-verdict $MinVerdict `
        --require-core
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "本机刷新失败，aggregator exit code=$ExitCode。请查看 dist-local/health.json。"
    }

    $ManifestPath = Join-Path $ProjectRoot "dist-local\manifest.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "刷新完成但未找到 dist-local/manifest.json。"
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Counts = $Manifest.counts
    $Quality = $Manifest.node_quality
    Write-Host "本机实测完成（仅计数摘要，不显示节点明细）"
    Write-Host ("counts=" + (@{
        sources = $Counts.sources
        parsed = $Counts.parsed
        accepted = $Counts.accepted
        published = $Counts.published
    } | ConvertTo-Json -Compress))
    Write-Host ("node_quality=" + (@{
        candidates = $Quality.candidates
        tested = $Quality.tested
        verified = $Quality.verified
        stable = $Quality.stable
        fast = $Quality.fast
        failed = $Quality.failed
        not_tested_budget = $Quality.not_tested_budget
        published = $Quality.published
    } | ConvertTo-Json -Compress))
}
finally {
    Pop-Location
}
