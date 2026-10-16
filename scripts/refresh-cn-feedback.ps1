# 一键刷新大陆可用清单（/cn 订阅）：
#   本机实测线上订阅 -> 写入 cn-feedback/latest.json -> 推送仓库 -> 触发云端重建 /cn
# 用途与边界：一次性输入，不是云端运行依赖；电脑关机不影响云端自动更新。
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$repo = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repo
$env:PYTHONIOENCODING = 'utf-8'

Write-Host '============================================='
Write-Host ' 大陆可用清单刷新（本机直连实测，约 8-10 分钟）'
Write-Host '============================================='

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw '未找到 python 命令：请先安装 Python 3.11+ 并加入 PATH。'
}

Write-Host '[1/4] 同步最新代码...'
git pull --rebase --autostash origin main
if ($LASTEXITCODE -ne 0) {
    throw '同步代码失败：请检查网络；若重试仍失败，请把本窗口截图发给 AI 管家。'
}

Write-Host '[2/4] 开始实测（请勿关闭窗口）...'
python 'scripts\cn_feedback_probe.py'
if ($LASTEXITCODE -ne 0) {
    throw '实测失败：请把本窗口截图发给 AI 管家。'
}

Write-Host '[3/4] 提交并推送结果...'
git add -- cn-feedback/latest.json
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host '  （结果与上次一致，无需提交）'
} else {
    git commit -m ("cn-feedback: refresh from local probe " + (Get-Date -Format 'yyyy-MM-dd HH:mm')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '提交失败：请把本窗口截图发给 AI 管家。' }
    $pushed = $false
    foreach ($attempt in 1..3) {
        git pull --rebase origin main | Out-Null
        if ($LASTEXITCODE -ne 0) { continue }
        git push origin HEAD:main
        if ($LASTEXITCODE -eq 0) { $pushed = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $pushed) {
        throw '推送失败：请把本窗口截图发给 AI 管家。'
    }
}

Write-Host '[4/4] 触发云端重建（/cn 订阅）...'
$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($gh) {
    gh workflow run auto-refresh.yml --ref main 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host '  已触发云端更新。'
    } else {
        Write-Host '  触发失败（不影响结果）：云端会在下一轮自动更新。'
    }
} else {
    Write-Host '  未检测到 gh 命令：云端会在下一轮自动更新。'
}

Write-Host ''
Write-Host '完成！约 10-15 分钟后 /cn 订阅自动生效：'
Write-Host 'https://cloudcat214.github.io/clash-subscription-aggregator/cn/clash/config.yaml'
