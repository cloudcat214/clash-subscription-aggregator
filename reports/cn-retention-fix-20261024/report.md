# /cn 保留率修复验收报告（2026-10-24）

## 结论

三项修复全部落地并已上线验证：

1. `blocked.json` 过期后整份忽略（`blocked_applied=false`），不再压缩 `/cn`。
2. `/cn` 不再依赖“当前发布的 N 个节点”：云反馈为每个 on 节点携带完整配置快照，发布集换血时用快照补入；新增 `--max-nodes`（默认 400，上限 800）。
3. 发布选择加入粘性：上一版 `docs/dist/clash/config.yaml` 中出现的 `node_key` 优先保留，行为确定性、可单测。

两轮线上结果：`/cn` node_key 集合保留率 **100.0%**（62/62），Jaccard **95.4%**（62/65），达到 ≥90% 的目标。

## 改动清单

| 类别 | 文件 | 说明 |
|---|---|---|
| 构建器 | `scripts/build_cn_channel.py` | 黑名单过期判定（`expires_at` 或 `generated_at+ttl_hours`）、`blocked_applied`/`blocked_expires_at`、快照补入、`--max-nodes`、必需字段校验、`from_published`/`from_snapshot` 计数 |
| 云扩展 | `scripts/expand_cn_feedback.py` | 输出 `nodes: {key: node}` 快照（仅 on）；旧 name-hash key 自动迁移到新身份 |
| 客户端审计 | `scripts/client_audit_loaded.py` | blocked.json 统一为 `names + ttl_hours + expires_at + generated_at` |
| 发布选择 | `aggregator/pipeline.py` | `sticky_publish_order`：上一版发布集优先，池内顺序做 tie-break；`_previous_publish_keys` 读取上一版 `docs/dist` |
| 身份/池 | `aggregator/quality.py`、`aggregator/parsing.py`、`aggregator/verified_pool.py`、`aggregator/failed_pool.py` | 协议字段哈希身份；池加载时兼容旧 key；verified/failed 迁移重叠时 verified 优先，不再整份冷启动 |
| 工作流 | `.github/workflows/auto-refresh.yml` | `/cn` 构建显式传 `--max-nodes 400` |
| 测试 | `tests/test_cn_channel.py`、`tests/test_expand_cn_feedback.py`、`tests/test_pipeline.py`、`tests/test_failed_pool.py`、`tests/test_node_identity.py` 等 | 新增过期/未过期、快照补入、截断、旧 key 迁移、粘性排序、池重叠测试 |

提交：

- `465c020` fix: keep cn channel stable across publish rotation
- `5a8771a` fix: migrate legacy feedback keys during cloud expansion
- `b1b2bec` fix: resolve verified/failed pool overlap after identity migration

## 验证命令与结果

| 命令 | 结果 |
|---|---|
| `python -m pytest -q -p no:cacheprovider` | **198 passed**（基线 171+） |
| `python -m ruff check .` | All checks passed |
| `python -m compileall -q aggregator scripts tests` | 退出码 0 |
| workflow YAML 解析（yaml.safe_load × 3） | `workflow yaml ok` |

## 两轮线上验收

触发方式：`gh workflow run auto-refresh.yml --ref main`，两轮均成功。

| 轮次 | run id | 提交 | `/cn` manifest |
|---|---|---|---|
| A | 40040754408 | `47cf8ff` | selected=62, from_published=62, from_snapshot=0, blocked_applied=false |
| B | 40041383970 | `34cd77e` | selected=65, from_published=64, from_snapshot=1, blocked_applied=false |

A 轮：`source_published=253`，`feedback_extra.stable=264`，`snapshots=62`，`blocked.skipped_reason=expired`。
B 轮：`source_published=313`，`feedback_extra.stable=266`，`snapshots=65`，`blocked.skipped_reason=expired`。

### `/cn` 集合交集

| 指标 | 数值 |
|---|---|
| A node_key 数 | 62 |
| B node_key 数 | 65 |
| A ∩ B | 62 |
| 保留率 `|A∩B| / |A|` | **100.0%** |
| Jaccard `|A∩B| / |A∪B|` | **95.4%** |

A 轮全部 62 个成员在 B 轮全部保留；B 轮新增 3 个，其中 1 个来自快照补入（`from_snapshot=1`），证明发布集变化不再导致 `/cn` 丢成员。

### `docs/dist` 换血

| 对比 | 结果 |
|---|---|
| A → B 规模 | 253 → 313 |
| 名字换血 | 5.1%（13/253） |
| node_key 换血 | 5.1%（13/253，与名字完全一致，无改名型流失） |
| 修复前历史样本 1（`14bf421`→`a31c2c1`） | 11.5%（800→800） |
| 修复前历史样本 2（`a31c2c1`→`2be0d25`） | 1.7%（800→800） |

说明：A→B 期间发布集尚未达到 800 上限（253→313），截断未发生，因此粘性排序本轮没有机会发挥；这 5.1% 全部是探测淘汰造成的真实身份流失，与命名无关。修复前两次历史采样为 11.5% / 1.7%（均值 6.6%，审计估计 ~4%），当前 5.1% 处于同一量级且更低。

### 线上部署核对

直接读取 Pages 线上文件，与仓库一致：

- `https://cloudcat214.github.io/clash-subscription-aggregator/cn/manifest.json` → `selected=65, from_published=64, from_snapshot=1, blocked_applied=false`
- `.../dist/manifest.json` → `published=313, parsed=27957, accepted=22276`

## 未完成项 / 风险 / 观察

1. **一次冷启动副作用（已修复根因）**：首次推送后的 run `40039388764` 因旧池在身份迁移后出现 verified/failed 重叠，被判 `pool cache semantic validation failed` 而冷启动，发布集从 800 掉到 116，`/cn` 当轮只有 31。已在 `b1b2bec` 改为“verified 优先、丢弃重叠 failed 项”，下一轮池恢复成功（`pool_retested=116`，published 116→253→313）。发布集仍在重建，尚未回到 800。
2. **`feedback_extra.stable` 含历史孤儿 key**：cloud.json 中约 200 个旧 key 在迁移时找不到对应节点（既不在当前发布集、也无快照），它们不参与渲染，只影响 manifest 的 stable 计数。不影响 `/cn` 选择；后续可加一次性清理（未做，避免重新引入“缺席即淘汰”的收缩问题）。
3. **粘性排序在发布集 <800 时无可观测效果**：逻辑已实现并由单测覆盖（`tests/test_pipeline.py::test_sticky_publish_order_prefers_previous_members`），需等池恢复到 800 以上才在线上生效。
4. **调度任务偶发失败**：run `40041241030`（schedule）在探测阶段报 `probe_direct_control_failed` 并退出，未发布任何产物；属探测控制目标的外部瞬时失败，重试轮（本轮 B）成功。非本次代码缺陷。
5. `blocked.json` 当前仍是 2026-10-18 的本地审计结果（`expires_at=2026-10-21`），已按预期整份失效。下一次本地 `client_audit_loaded.py` 运行会写入新结构并自动续期。

## 产物

- `reports/cn-retention-fix-20261024/round-a-cn.yaml`
- `reports/cn-retention-fix-20261024/round-a-manifest.json`
- `reports/cn-retention-fix-20261024/round-a-dist.yaml`
- `reports/cn-retention-fix-20261024/round-b-cn.yaml`
- `reports/cn-retention-fix-20261024/round-b-manifest.json`
- `reports/cn-retention-fix-20261024/round-b-dist.yaml`
- `reports/cn-retention-fix-20261024/dist-baseline.json`
