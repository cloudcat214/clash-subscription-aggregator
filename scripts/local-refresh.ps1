param(
    [int]$MaxNodes = 150,
    [int]$Rounds = 3,
    [double]$Timeout = 5,
    [int]$Concurrency = 6,
    [ValidateSet("stable", "verified", "fast")]
    [string]$MinVerdict = "stable",
    [string]$Core,
    [string]$ProbeInterface
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

function Get-DirectProbeInterface {
    $excluded = 'Meta|Tunnel|Wintun|TAP|VPN'
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        $_.Status -eq "Up" -and
        $_.Name -notmatch $excluded -and
        $_.InterfaceDescription -notmatch $excluded -and
        $_.Virtual -ne $true
    })
    if ($adapters.Count -eq 0) {
        throw "未找到状态为 Up 的物理网卡。"
    }

    $adapterByIndex = @{}
    foreach ($adapter in $adapters) {
        $adapterByIndex[[int]$adapter.ifIndex] = $adapter
    }
    $routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 |
        Sort-Object RouteMetric, ifIndex)
    foreach ($route in $routes) {
        if ($adapterByIndex.ContainsKey([int]$route.ifIndex)) {
            return $adapterByIndex[[int]$route.ifIndex]
        }
    }
    return ($adapters | Sort-Object {
        if ($_.Name -match 'WLAN|Wi-?Fi|Ethernet|以太网') { 0 } else { 1 }
    }, ifIndex | Select-Object -First 1)
}

if ([string]::IsNullOrWhiteSpace($ProbeInterface)) {
    $SelectedAdapter = Get-DirectProbeInterface
    $ProbeInterface = [string]$SelectedAdapter.Name
} else {
    $SelectedAdapter = Get-NetAdapter -Name $ProbeInterface -IncludeHidden -ErrorAction SilentlyContinue
    if ($null -eq $SelectedAdapter -or $SelectedAdapter.Status -ne "Up") {
        throw "手动指定的 ProbeInterface 不存在或未处于 Up：$ProbeInterface"
    }
}
Write-Host ("直连探测网卡=" + $SelectedAdapter.Name + "; ifIndex=" + $SelectedAdapter.ifIndex + "; description=" + $SelectedAdapter.InterfaceDescription)

Push-Location $ProjectRoot
try {
    & python -m aggregator run `
        --config config/sources.yaml `
        --output dist-local `
        --state state-local `
        --no-private `
        --mihomo $Core `
        --probe `
        --probe-interface $ProbeInterface `
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
