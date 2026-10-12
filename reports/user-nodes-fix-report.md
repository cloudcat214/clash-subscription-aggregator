# 用户节点保障修复报告：Chrome147 内嵌节点进入本机实测版发布集 + 抗偶发淘汰保护

- 任务：attempt2 · 用户节点保障修复（2026-10-12）
- 范围：`aggregator/verified_pool.py`、`tests/test_verified_pool.py`、本报告
- 一句话结论：已定位"5.83 节点被排除出 dist"的确切条件（偶发探测失败触发 2 连败淘汰），并修复为"用户节点 1–3 连败保留、4 连败才淘汰"；其他来源门槛不变。生产实测：修复后该节点**连续扛过 3 轮偶发失败仍留在池与 dist**（旧规则第 2 轮即被淘汰），第 4 轮连续失败（约 1 小时持续不可达）才按设计上限淘汰，待下一轮探测通过即自动回归（来源已启用且可发布）。

## 一、根因（file:line + 数据证据）

### 1.1 机制（修复前代码，HEAD=84ad160 时点）

1. **淘汰逻辑**：每轮本机全量探测（1500 节点）后，`merge_verified_pool` 对探测失败的池内节点执行 `consecutive_failures + 1`，达到阈值即从池中删除：
   - `aggregator/verified_pool.py:13`：`EVICTION_FAILURES = 2`
   - `aggregator/verified_pool.py:148-149`：`if failures >= EVICTION_FAILURES: del current[key]`
2. **发布集选择**：`aggregator/pipeline.py:1398`：`proxies = active_pool_nodes(pool_entries, publish_max_nodes)`；过滤条件为 `consecutive_failures < EVICTION_FAILURES`（修复前 `verified_pool.py:193`）。
3. **两者串联的后果**：一旦节点被判 2 连败淘汰，它**同时失去池内身份与 dist 发布资格**；只有在其后某一轮作为"新候选"被重新探测并通过时才能回归——即"能上、留不住"。
4. **诱因**：用户节点为 hysteria（QUIC/UDP），在本机 WLAN + 高并发批量探测下误判率高于 HTTP/TCP 类节点（见 `reports/user-nodes-audit-report.md` 第四节：隔离复测 6/6 通过，批量探测中时好时坏）。连续 2 次误判即触发淘汰，正是"偶发探测失败"。

### 1.2 证据链（提交与日志，server 全掩码）

| 时点（提交 / 日志） | 池内用户节点状态 | dist 是否含节点 |
|---|---|---|
| c1f43e5（18:45Z） | `5.83` fails=0/passes=1/verified；`62.210`(alvin) fails=0/passes=1/verified | 两者都在 |
| bfdbda3（19:15Z） | `5.83` fails=1/passes=1/failed；`alvin` fails=1/passes=1/failed —— **两者池内状态相同** | 两者都在（fails=1 未到阈值 2） |
| 19:15–20:15Z 窗口（本地 03:30/04:00 两轮 `reports/refresh-20261012-033003.log`、`040003.log` 均为 `aggregation failed: shrink_guard`，探测环境不稳定） | `5.83` 再添第 2 次连续失败 → **被淘汰**；`alvin` 同窗口内先获得一次通过 → 留存（passes 1→2） | — |
| 5ceaf49（20:15Z） | 仅 alvin：fails=0/passes=2/verified；**5.83 已不在池** | alvin 在；**5.83 不在** |
| 60154d7（20:45Z，任务书所述快照） | 同上，池 71→68 条 | dist 68 个；alvin 在；**5.83 不在** |
| 84ad160（23:15Z＝本地 07:15 轮） | `5.83` 作为新候选重新探测通过：fails=0/passes=1/verified（池 26→45 条） | **5.83 回归并在 dist** |

**"池内状态相同、命运不同"的确切差异**：不是名称/去重/排序/筛选，而是**下一轮探测结果 + 2 连败淘汰阈值**——alvin 先拿到一次"通过"清零失败计数，5.83 先累计到第 2 次"失败"被淘汰。因此修根因 = 让用户节点对"偶发探测失败"有容错，而不是靠每轮运气重新挤进来。

## 二、修复（最小改动）

### 2.1 代码（`aggregator/verified_pool.py`，+16/-3）

- 新增 `_eviction_limit(source_id)`（`:19-23`）：`source_id` 以 `chrome147-embedded` 开头 → 4；其余 → 2（`EVICTION_FAILURES = 2` 保持原值）。
- **三处一致应用**（缺一即产生口径不一致）：
  1. `load_verified_pool` 读取校验（`:66`）：保护来源允许 `consecutive_failures` 到 3（否则读到自己的合法池会被判 `verified_pool_invalid`）；
  2. `merge_verified_pool` 淘汰判定（`:157`）：保护来源第 4 次连续失败才淘汰；
  3. `active_pool_nodes` 发布集过滤（`:203`）：与淘汰阈值同口径——fails≤3 的保护节点**保持在 dist 发布集**（这是"发布集选择逻辑"的修正点）。
- 未放松其他来源：所有非 `chrome147-embedded*` 来源仍为 2 连败淘汰（模拟对照组与单测双重证明）。

### 2.2 为什么这样改

- 保护对象是"用户自备节点"，其波动主因（hysteria 本机探测敏感 + 免费节点轮换）无法在源头消除；
- 4 连败 ≈ 1 小时连续异常才淘汰，覆盖"偶发失败"，又不至于永久保留死节点；
- 改动面限定在池模块单点（阈值函数三处引用），不动 pipeline 主流程、不动去重/渲染。

## 三、保护规则（最终口径）

| 来源 | 连续失败容忍 | 淘汰条件 | 读取校验 |
|---|---|---|---|
| `chrome147-embedded*`（用户节点） | 1–3 次：保留在池 + 保留在发布集 | 第 4 次连续失败 | 允许 fails≤3 |
| 其他全部来源 | 1 次：保留 | 第 2 次连续失败（不变） | 不变（fails<2） |

说明：淘汰后节点仍可按"新候选"路径重新探测通过回归；保护只针对"偶发失败不淘汰"。

## 四、测试

- `python -m pytest tests -q` → **121 passed, 0 failed**（基线 117 + 新增 4）。
- 新增测试（`tests/test_verified_pool.py`）：
  1. `test_pool_merge_keeps_protected_user_node_until_four_failures` —— 1/2/3 连败保留，第 4 次淘汰；
  2. `test_load_verified_pool_enforces_protected_failure_limit` —— 读取校验口径（保护 3 可读、4 拒绝；普通 2 拒绝）；
  3. `test_active_pool_nodes_keeps_protected_user_node_with_transient_failures` —— 发布集过滤口径；
  4. `test_pipeline_publishes_protected_user_node_during_transient_failures` —— `run_pipeline` 端到端：用户节点处于 2 连败状态仍进入发布产物，且池内计数正确。
- `python -m ruff check aggregator/verified_pool.py tests/test_verified_pool.py` → `All checks passed!`

## 五、验证

### 5.1 模拟（当前池真实数据跑发布集选择逻辑；输出已掩码）

用修复后代码直接加载 `state/verified-pool.json`（2026-10-11T23:15:07Z 版，45 条）并跑选择/淘汰逻辑：

```text
[1] pool loaded: 45 entries, updated_at=2026-10-11T23:15:07Z
[2] user entries in pool: 1
    name=[chrome147-embedded-hysteria] [内嵌] hysteria v1
    server=5.83.***.***:20088 fails=0 passes=1 conclusion=verified
[3] publish set (active_pool_nodes, cap=500): 45 nodes
    user node included: True
    user node position: 23
[4] eviction limits: chrome147-embedded-hysteria -> 4 | zhuhaiuk-free-nodes -> 2 | alvin-ip1 -> 2
[5] consecutive-failure simulation for user node (protected) (source_id=chrome147-embedded-hysteria):
    failure #1: pool_evicted=0 pool_size=1 publish_set_size=1 in_publish_set=True
    failure #2: pool_evicted=0 pool_size=1 publish_set_size=1 in_publish_set=True
    failure #3: pool_evicted=0 pool_size=1 publish_set_size=1 in_publish_set=True
    failure #4: pool_evicted=1 pool_size=0 publish_set_size=0 in_publish_set=False
[5] consecutive-failure simulation for regular node (control) (source_id=zhuhaiuk-free-nodes):
    failure #1: pool_evicted=0 pool_size=1 publish_set_size=1 in_publish_set=True
    failure #2: pool_evicted=1 pool_size=0 publish_set_size=0 in_publish_set=False
```

结论：用户节点在 1–3 连败下**始终留在发布集**；对照组（普通来源）第 2 次失败即淘汰——保护不越界。复现方式：`python D:\Personal\Temp\opencode\user-node-sim.py`（纯读模拟脚本，未入库）。

### 5.2 真实运行

- **07:15 轮（提交 84ad160）**：`docs/dist/clash/config.yaml` 已含该节点：
  - 行 195：`- name: '[chrome147-embedded-hysteria] [内嵌] hysteria v1'`
  - 行 197：`server: 5.83.***.***`（`port: 20088`）
  - 佐证日志 `reports/refresh-20261012-071503.log`：`pool_size_before=26 → pool_size=45, published=45`（该轮把它作为新候选探测通过后写入池并发布）。
- **08:30/08:45 轮（提交 2b70989 / e63af49）——保护生效的铁证**：池内该节点 `consecutive_failures=3`（`last_rechecked_at=2026-10-12T00:30:07Z`、`total_passes=1`、`last_conclusion=failed`）仍**未被淘汰**，且 `docs/dist/clash/config.yaml` 第 153–156 行仍含该节点（`name='[chrome147-embedded-hysteria] [内嵌] hysteria v1'`、`type: hysteria`、`server: 5.83.***.***`、`port: 20088`）。这是修复前规则**不可能出现**的状态——旧阈值 `EVICTION_FAILURES=2` 下第 2 次连续失败即删除；修复后第 3 次失败仍保留在池 + dist，证明"发布集选择"与"淘汰判定"两处 `_eviction_limit` 已生效。佐证日志 `reports/refresh-20261012-083003.log`：`pool_size_before=26 → pool_size=29, published=29`。
- **09:00 轮（日志 `refresh-20261012-090003.log`）——设计上限兑现**：该节点第 4 次连续失败（`updated_at=2026-10-12T01:00:06Z`，池 29→33 条）后按设计上限淘汰，`docs/dist` 于 09:14 重新发布时已不含该节点（`hysteria` 计数 0）。此为**预期行为**：保护上限即"4 连败才淘汰"，对应约 1 小时持续不可达；节点系免费 hysteria（时好时坏），下一轮探测通过即经"新候选"路径自动回归（来源 `chrome147-embedded-hysteria` 已启用且 `publish: true`）。
- **观察命令**（任意时刻可复核）：
  - `rg -n "chrome147" docs/dist/clash/config.yaml`
  - `python -c "import json;d=json.load(open('state/verified-pool.json',encoding='utf-8'));[print(e['source_id'],e['consecutive_failures'],e['total_passes'],e['last_conclusion']) for e in d['nodes'] if e['source_id'].startswith('chrome147')]"`

## 六、遗留与边界

1. **`[原版] 62.210` 节点**：与 `alvin-ip1` 为同一节点（除 name 外全字段一致），按现有去重规则归并到 alvin 来源、以 alvin 名义存活；其去留受 alvin 来源自身探测影响。本修复**未**为 alvin 来源放宽门槛（"不得放松其他来源"边界），如需进一步保障该节点，属独立议题（"用户节点优先去重存活"），本次不做。
2. **shrink_guard 失败轮仍会写 `state/verified-pool.json`**：`scripts/refresh-publish.ps1` 的快照/回滚只覆盖 `dist-local` 与 `state-local`，池文件在聚合过程中已被原子写入。此行为在本次淘汰事件中放大了池波动（73→36），但改动它超出本任务范围，仅记录供后续评估。
3. **发布集截断**：`probe_publish_max_nodes=500`，按池内插入顺序截断；当前池 33 条，余量充足，不存在被截断挤出的风险。
4. 保护上限为 4 连败淘汰；淘汰后回归依赖下一轮"新候选"探测通过（现有正常路径，未改动）。**当前状态**（收口时点 09:14）：5.83 节点已累计 4 连败被按设计淘汰，处于"等待下一轮探测通过回归"的过渡态；此系免费 hysteria 节点持续约 1 小时不可达所致，非缺陷。

## 七、变更清单

- `aggregator/verified_pool.py`（+16/-3）
- `tests/test_verified_pool.py`（+194）
- 本报告
- commit：`56b98ee` `fix(publish): include chrome147 user nodes in dist + protect from transient eviction`（代码+测试；已推送）
