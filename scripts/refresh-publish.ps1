[CmdletBinding()]
param(
    [switch]$Publish,
    [ValidateRange(0, 2000)]
    [int]$MinStable = 5,
    [ValidateRange(1, 2000)]
    [int]$MaxNodes = 1500,
    [string]$Output = "dist-local",
    [string]$State = "state-local",
    [string]$VerifiedPool = "state/verified-pool.json",
    [string]$ProbeInterface,
    [string]$Core
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDirectory = Join-Path $ProjectRoot "reports"
$LogPath = Join-Path $LogDirectory "refresh-$Timestamp.log"
$TranscriptStarted = $false
$LocationPushed = $false
$SnapshotRoot = $null
$OutputSnapshot = $null
$StateSnapshot = $null
$OutputHadSnapshot = $false
$StateHadSnapshot = $false

function Resolve-ProjectPath {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ([IO.Path]::IsPathRooted($Value)) {
        return [IO.Path]::GetFullPath($Value)
    }
    return [IO.Path]::GetFullPath((Join-Path $ProjectRoot $Value))
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

function Save-Snapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        return $false
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
    return $true
}

function Restore-Snapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Snapshot,
        [Parameter(Mandatory = $true)][bool]$HadSnapshot
    )

    if (Test-Path -LiteralPath $Target) {
        Remove-Item -LiteralPath $Target -Recurse -Force
    }
    if ($HadSnapshot -and (Test-Path -LiteralPath $Snapshot)) {
        Move-Item -LiteralPath $Snapshot -Destination $Target
    }
}

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git 命令失败，exit code=$LASTEXITCODE。"
    }
}

$MaterialArtifactPaths = @(
    "docs/dist/clash/config.yaml",
    "docs/dist/clash/providers/aggregate.yaml",
    "docs/dist/sing-box/config.json"
)

function Get-MaterialHash {
    param([Parameter(Mandatory = $true)][string]$Text)

    $normalized = $Text -replace "`r`n", "`n"
    $normalized = $normalized -replace "`r", "`n"
    $normalized = [regex]::Replace(
        $normalized,
        '(?m)^[\t ]*"?(?:generated_at|updated_at|created_at|timestamp|last_checked|refreshed_at)"?\s*:\s*.*(?:\r?\n|$)',
        ""
    ).Trim()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))
        )).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-FileMaterialHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-MaterialHash (Get-Content -LiteralPath $Path -Raw -Encoding UTF8)
}

function Get-HeadMaterialHash {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $text = (& git show ("HEAD:{0}" -f $RelativePath) 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return Get-MaterialHash $text
}

function Test-MaterialChange {
    foreach ($relativePath in $MaterialArtifactPaths) {
        $localPath = Join-Path $ProjectRoot $relativePath
        $localHash = Get-FileMaterialHash $localPath
        $headHash = Get-HeadMaterialHash $relativePath
        if ([string]::IsNullOrWhiteSpace($headHash) -or $localHash -ne $headHash) {
            return $true
        }
    }
    return $false
}

$PauseLockPath = Join-Path $ProjectRoot ".cache\publish-pause.lock"
if ($Publish -and (Test-Path -LiteralPath $PauseLockPath)) {
    Write-Host "publish paused by temporary migration lock; this cycle skips all work."
    exit 0
}

try {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    Start-Transcript -LiteralPath $LogPath -Force | Out-Null
    $TranscriptStarted = $true
    Push-Location $ProjectRoot
    $LocationPushed = $true

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
    if ([string]::IsNullOrWhiteSpace($Core) -or
        -not (Test-Path -LiteralPath $Core -PathType Leaf)) {
        throw "找不到 verge-mihomo.exe。请使用 -Core 指定 Mihomo 可执行文件路径。"
    }

    if ([string]::IsNullOrWhiteSpace($ProbeInterface)) {
        $SelectedAdapter = Get-DirectProbeInterface
        $ProbeInterface = [string]$SelectedAdapter.Name
        Write-Host ("自动检测直连探测网卡=" + $SelectedAdapter.Name +
            "; ifIndex=" + $SelectedAdapter.ifIndex +
            "; description=" + $SelectedAdapter.InterfaceDescription)
    } else {
        $SelectedAdapter = Get-NetAdapter -Name $ProbeInterface -IncludeHidden -ErrorAction SilentlyContinue
        if ($null -eq $SelectedAdapter -or $SelectedAdapter.Status -ne "Up") {
            throw "手动指定的 ProbeInterface 不存在或未处于 Up：$ProbeInterface"
        }
        Write-Host ("使用指定直连探测网卡=" + $SelectedAdapter.Name +
            "; ifIndex=" + $SelectedAdapter.ifIndex +
            "; description=" + $SelectedAdapter.InterfaceDescription)
    }

    $OutputPath = Resolve-ProjectPath $Output
    $StatePath = Resolve-ProjectPath $State
    $VerifiedPoolPath = Resolve-ProjectPath $VerifiedPool
    $SnapshotRoot = Join-Path ([IO.Path]::GetTempPath()) "clash-refresh-$Timestamp-$PID"
    New-Item -ItemType Directory -Path $SnapshotRoot -Force | Out-Null
    $OutputSnapshot = Join-Path $SnapshotRoot "output"
    $StateSnapshot = Join-Path $SnapshotRoot "state"
    $OutputHadSnapshot = Save-Snapshot $OutputPath $OutputSnapshot
    $StateHadSnapshot = Save-Snapshot $StatePath $StateSnapshot

    $arguments = @(
        "-m", "aggregator", "run",
        "--config", "config/sources.yaml",
        "--output", $OutputPath,
        "--state", $StatePath,
        "--verified-pool", $VerifiedPoolPath,
        "--no-private",
        "--mihomo", $Core,
        "--probe",
        "--probe-backend", "delay",
        "--probe-interface", $ProbeInterface,
        "--probe-max-nodes", $MaxNodes,
        "--probe-rounds", 3,
        "--probe-timeout", 8,
        "--probe-concurrency", 12,
        "--probe-min-verdict", "stable",
        "--require-core"
    )
    & python @arguments
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Restore-Snapshot $OutputPath $OutputSnapshot $OutputHadSnapshot
        Restore-Snapshot $StatePath $StateSnapshot $StateHadSnapshot
        throw "本机刷新失败，aggregator exit code=$ExitCode。"
    }

    $ManifestPath = Join-Path $OutputPath "manifest.json"
    $HealthPath = Join-Path $OutputPath "health.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $HealthPath -PathType Leaf)) {
        Restore-Snapshot $OutputPath $OutputSnapshot $OutputHadSnapshot
        Restore-Snapshot $StatePath $StateSnapshot $StateHadSnapshot
        throw "刷新完成但 manifest.json 或 health.json 缺失。"
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Health = Get-Content -LiteralPath $HealthPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Counts = $Manifest.counts
    $Quality = $Manifest.node_quality
    $Stable = [int]$Quality.stable
    $PublishedCount = [int]$Quality.published
    Write-Host "本机直连实测完成（仅计数摘要，不显示节点明细）"
    Write-Host ("counts=" + (@{
        sources = $Counts.sources
        parsed = $Counts.parsed
        accepted = $Counts.accepted
        published = $Counts.published
    } | ConvertTo-Json -Compress))
    Write-Host ("probe_quality=" + (@{
        candidates = $Quality.candidates
        tested = $Quality.tested
        stage1_tested = $Manifest.verification.stage1_tested
        stage1_passed = $Manifest.verification.stage1_passed
        stage2_tested = $Manifest.verification.stage2_tested
         stage2_stable = $Manifest.verification.stage2_stable
         stable = $Stable
         published = $Quality.published
         probe_queue = $Manifest.verification.probe_queue
         pool_probe_candidates = $Manifest.verification.pool_probe_candidates
         pool_size_before = $Manifest.verification.pool_size_before
         pool_size = $Manifest.verification.pool_size
         pool_retested = $Manifest.verification.pool_retested
         new_candidates_tested = $Manifest.verification.new_candidates_tested
         retained_count = $Manifest.verification.retained_count
     } | ConvertTo-Json -Compress))

    if ([string]$Health.fallback -eq "last-known-good") {
        Restore-Snapshot $OutputPath $OutputSnapshot $OutputHadSnapshot
        Restore-Snapshot $StatePath $StateSnapshot $StateHadSnapshot
        throw "本轮使用 last-known-good 回退，拒绝继续发布。"
    }
    if ($PublishedCount -lt $MinStable) {
        if ($Publish) {
            Restore-Snapshot $OutputPath $OutputSnapshot $OutputHadSnapshot
            Restore-Snapshot $StatePath $StateSnapshot $StateHadSnapshot
            throw "published=$PublishedCount 小于 MinStable=$MinStable，拒绝发布并保留旧内容。"
        }
        Write-Warning "published=$PublishedCount 小于 MinStable=$MinStable；仅保留本机刷新结果，不执行发布。"
    }

    if ($Publish -and $PublishedCount -ge $MinStable) {
        $credentialHelper = (& git config --get credential.helper 2>$null | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($credentialHelper)) {
            if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
                throw "git credential.helper 为空且未找到 gh，无法设置 GitHub 凭据。"
            }
            & gh auth setup-git
            if ($LASTEXITCODE -ne 0) {
                throw "gh auth setup-git 失败，exit code=$LASTEXITCODE。"
            }
        }

        $DocsPath = Resolve-ProjectPath "docs"
        $DocsTarget = Join-Path $DocsPath "dist"
        $DocsStaging = Join-Path $DocsPath ".dist-staging-$Timestamp-$PID"
        $DocsBackup = Join-Path $DocsPath ".dist-backup-$Timestamp-$PID"
        if (Test-Path -LiteralPath $DocsStaging) {
            Remove-Item -LiteralPath $DocsStaging -Recurse -Force
        }
        New-Item -ItemType Directory -Path $DocsStaging -Force | Out-Null
        Copy-Item -Path (Join-Path $OutputPath "*") -Destination $DocsStaging -Recurse -Force
        $MovedDocs = $false
        try {
            if (Test-Path -LiteralPath $DocsTarget) {
                Move-Item -LiteralPath $DocsTarget -Destination $DocsBackup
                $MovedDocs = $true
            }
            Move-Item -LiteralPath $DocsStaging -Destination $DocsTarget
        } catch {
            if ($MovedDocs -and (Test-Path -LiteralPath $DocsBackup) -and
                -not (Test-Path -LiteralPath $DocsTarget)) {
                Move-Item -LiteralPath $DocsBackup -Destination $DocsTarget
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $DocsStaging) {
                Remove-Item -LiteralPath $DocsStaging -Recurse -Force
            }
            if (Test-Path -LiteralPath $DocsBackup) {
                Remove-Item -LiteralPath $DocsBackup -Recurse -Force
            }
        }

        if (-not (Test-MaterialChange)) {
            Write-Host "no material change; skip commit/push."
        } else {
            Invoke-Git @("add", "--all", "--", "docs/dist")
            $CommitTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Invoke-Git @("commit", "-m", "refresh: verified nodes $CommitTime")
            Invoke-Git @("pull", "--rebase")
            Invoke-Git @("push", "origin", "main")
        }
    }
} catch {
    Write-Error $_
    exit 1
} finally {
    if ($LocationPushed) {
        Pop-Location
    }
    if ($SnapshotRoot -and (Test-Path -LiteralPath $SnapshotRoot)) {
        Remove-Item -LiteralPath $SnapshotRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
    }
}
