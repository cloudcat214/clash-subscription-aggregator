# 节点保留机制（verified node pool）收尾报告

日期：2026-10-11

## 一、设计说明

引入持久化「已验证节点池」（`state/verified-pool.json`），把「上轮探测合格」的节点及其完整配置、来源、时间戳、连续失败计数保留下来，跨刷新轮次复用，避免每轮都从零重测所有候选。

核心机制（对应 `aggregator/verified_pool.py` + `aggregator/pipeline.py`）：

1. **池持久化**：每条池记录保存 `key`（节点指纹）、`node`（完整节点配置：name/type/server/port/uuid/flow/tls/servername/client-fingerprint/reality-opts 等）、`source_id`（来源）、`first_seen_at` / `last_rechecked_at`（时间戳）、`last_conclusion`（最近结论）、`consecutive_failures`（连续失败计数）、`total_passes`（累计通过次数）。
2. **池内节点优先复检**：主动探测时，先取池内节点进入探测队列（`probe_queue=verified_pool_first`），剩余探测预算再分给新候选。
3. **连续失败 ≥ 2 才移出**：单次失败只累加 `consecutive_failures` 并保留；`consecutive_failures >= 2`（`EVICTION_FAILURES=2`）时才移出池。
4. **新候选跨来源均衡采样**：`round_robin_by_source` 按来源轮流取样，防止单一大来源把探测预算占满（见「根因诊断」）。
5. **发布集 = 池内有效节点**：发布时取 `active_pool_nodes`（`consecutive_failures < 2` 的池内节点）作为最终发布集合。
6. **防抖保护（jitter guard）**：沿用 shrink guard；当上轮发布 ≥ 10 个节点时，拟发布集低于上轮 50% 即跳过覆盖、保留旧产物，避免探测波动导致的发布骤降。

## 二、根因诊断

**现象**：公开发布节点数从 33 跌到 6。

**根因**：原探测队列用简单切片 `candidate_pool[:probe_max_nodes]`，排序后靠前的单一大来源节点把探测预算全部占满，其余来源的候选从未被探测、无法进入发布集，导致发布集骤降。

**修复**：① 池内节点优先复检（保留已验证节点）；② 新候选按来源轮询均衡采样（`round_robin_by_source`），保证每个来源都有节点被探测。两项叠加后，发布数恢复到 30。

## 三、生产运行证据

日志：`reports/refresh-20261011-171503.log`（本机 15 分钟刷新任务，`-Publish` 模式，17:28:16 完成）。

关键行（脱敏摘要，原文字段保留）：

- `counts={"sources":25,"accepted":4075,"parsed":4989,"published":30}`
- `probe_quality={"retained_count":30,"stage1_passed":57,"stable":10,"candidates":3877,"stage2_stable":27,"tested":1500,"pool_retested":31,"probe_queue":"verified_pool_first","published":30,"pool_size":30,"pool_size_before":31,"new_candidates_tested":1469,"stage2_tested":57,"pool_probe_candidates":31,"stage1_tested":1500}`

解读：`pool_size=30`（池内 30 个节点）、`pool_retested=31`（复检 31 次）、`retained_count=30`、`probe_queue=verified_pool_first`（池优先复检生效）、`published=30`（发布数从 6 涨到 30）。提交 `71c93f3`（refresh: verified nodes 2026-10-11 17:27:58）已随刷新任务推送成功（`98ebb5e..71c93f3  main -> main`）。

## 四、测试结果

`python -m pytest tests -q`：

- passed = 115（原有 109 + 新增 `tests/test_verified_pool.py` 6 个）
- failed = 0
- skipped = 0

新增用例覆盖：来源均衡采样、池合并/失败清零、连续两次失败才淘汰、池优先探测队列、池 shrink guard 50% 阈值、shrink guard 保留旧产物。

## 五、防抖说明

- 上轮发布节点数 < 10：沿用配置 `max_shrink_ratio`（默认 0，即不启用）。
- 上轮发布节点数 ≥ 10：`pool_shrink_ratio = max(max_shrink_ratio, 0.5)`，拟发布集低于上轮 50% 时触发 shrink guard，跳过覆盖并保留旧产物（`dist/clash/providers/aggregate.yaml` 等）。

## 六、遗留差异

无。任务要求的 a)~f) 六项均已实现并核实（见「设计说明」+ 测试）。

（附：收尾过程中修复一处 `.gitignore` 缺陷——原 `reports/` 为目录级忽略，导致 `!reports/retention-pool-report.md` 白名单失效；已改为 `reports/*` 使本报告可被 Git 纳管。）
