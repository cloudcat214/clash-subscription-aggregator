# 云端收口笔记（auto-refresh 补跑 + 产物校验 + README 校准）

- 日期：2026-10-12（本地 +08:00）
- 范围：`docs/auto` 云端频道（`.github/workflows/auto-refresh.yml`）
- 原则：只记录证据与判定；不改 workflow、不改代码、不处理发现的关键词。

## 1. 故障复述与判定（fail-safe，无坏发布）

- 失败 run：`38185656022`（schedule，2026-10-11T23:48:27Z 创建，用时 26s，conclusion=failure）。
- 关键日志（`gh run view 38185656022 --log-failed`）：
  - `2026-10-11T23:48:50Z aggregation failed: probe_direct_control_failed; last-known-good=False`
  - `##[error]Process completed with exit code 2.`
- 判定：聚合前置的“直连控制探测”失败即中止，**未产出任何提交**；`docs/auto/` 保持上一份好快照（manifest generated_at 2026-10-11T20:26:24Z，来自成功 run `38172199919`）。属 fail-safe 行为。
- 同一代码在 20:26Z 与本次补跑均成功 → 判定为 Runner 侧瞬时网络问题，非代码缺陷。

## 2. 手动补跑结果

- 命令：`gh workflow run auto-refresh.yml`（workflow_dispatch）。
- 新 run：`38191821783`，createdAt 2026-10-12T01:25:22Z（09:25:22 +08），updatedAt 01:29:15Z（09:29:15 +08）。
- 结论：**success**；总耗时 **3m53s**（job “Refresh and deploy cloud subscription” 3m48s）。
- 流程全绿：Checkout → Install → Download and verify Mihomo → Run cloud aggregation and probe → Stage → Commit changed auto artifacts → Deploy Pages。

## 3. 产物新鲜度证据（补跑后，`git pull --rebase` 已同步）

| 项 | 值 |
|---|---|
| manifest.json generated_at | **2026-10-12T01:25:35Z**（晚于 20:26:24Z，已刷新） |
| counts | published=500, sources=25, parsed=5935, accepted=5082 |
| docs/auto/clash/config.yaml proxies | **500**（>0） |
| manifest status | degraded（1/25 来源 `clashfree-daily` ParseError、空内容；不阻断发布） |
| node_quality | tested=1000 / verified=730 / published=500 / success_rate=0.744 |

## 4. 指定关键词记录（只记录，不处理）

- `5.83`：`docs/auto/clash/config.yaml:50`，为节点 `[chrome147-embedded-hysteria] [内嵌] hysteria v1` 的 server `5.83.129.153`。
- `chrome147`：共 5 处 —— `config.yaml:48/4398/4901`（节点名及组引用）、`manifest.json:318`、`health.json:303`（来源 id `chrome147-embedded-hysteria`）。

## 5. schedule 实测节奏（best-effort 调度证据）

来源：`gh run list --workflow=auto-refresh.yml --limit 100 --json event,createdAt,conclusion`（该 workflow 2026-10-11 建立，总计仅 7 次运行）：

| createdAt (UTC) | event | 结论 |
|---|---|---|
| 2026-10-11T16:22:37Z | schedule | success |
| 2026-10-11T20:26:12Z | schedule | success |
| 2026-10-11T23:48:27Z | schedule | failure |

- 实测 schedule 间隔：16:22→20:26 = **4h04m**；20:26→23:48 = **3h22m**。
- 23:48 失败后至 01:25Z 手动补跑前，**未见任何 schedule 重试**（若按 */15 应有 ≥6 次）。
- 结论：GitHub 对高频 schedule 为尽力而为调度，实测触发间隔 **数小时**，不能按“每 15 分钟”承诺；README 已按此校准。

## 6. README 改动

- 仅改“订阅地址”一节“云端自动版”一行（本机实测版行未动）：
  - 旧：`GitHub 云端每 15 分钟自动刷新，无需电脑开机。`
  - 新：`GitHub 云端自动刷新：每 15 分钟触发一次、无需电脑开机，GitHub 调度高峰时可能延后；本机实测版为 15 分钟可靠刷新。`

## 7. Housekeeping

- `config/tmp*.yaml` 检查：存在 `config/tmpgmo3zqbz.yaml`（mtime 2026-10-12 09:30:33 +08）；但检查时**本机 refresh 进程正在运行**（PID 62416，`python -m aggregator run … --probe`）且文件新鲜（<30 分钟），判定为在用临时文件，**未删除**。
- `git status --short`：补跑后除上述未跟踪文件外无其他残留。

## 8. 遗留

1. 云端 schedule 频率不可依赖（数小时级延后）；准点刷新目前只有本机实测版（开机时 15 分钟）。
2. `clashfree-daily` 来源 ParseError（空内容）：观察是否源端偶发，本次不处理。
3. CI 注解：Node.js 20 弃用提示（actions/* 被强制跑在 Node 24）——GitHub 平台提示，本次不处理。
