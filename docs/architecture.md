# 聚合器架构与安全边界

## 数据流

1. 仓库将公开来源清单 `config/sources.yaml` 入库，其中包含公开来源 URL、来源元数据和 `private` 来源的环境变量占位；不含订阅令牌、节点凭据或私有正文。配置将 `public` 与 `private` 来源分开；Pull Request CI 只运行合成数据的离线测试，受门禁的定时/手动发布才运行来源聚合。
2. `aggregator.fetch` 只允许显式信任的 HTTPS host。每一跳 redirect 都重新解析、校验 host/IP 并用 `curl --resolve` 固定地址；受控例外只允许 `raw.githubusercontent.com` 与精确地址 `198.18.0.21`、`198.18.1.48`，不能放行整个 `198.18.0.0/15`。IPv4-mapped IPv6（`::ffff:a.b.c.d`）先解包为 IPv4；常见 NAT64 `64:ff9b::/96` 与 `64:ff9b:1::/48` 显式拒绝。`100.64.0.0/10`、文档/基准测试地址、私网、回环、metadata 和链路本地地址均拒绝。
3. `aggregator.parsing` 解析 Clash YAML/JSON、Base64 和 URI，保留协议的传输、TLS、Reality、插件等结构；不做节点拨测。
4. `aggregator.probe` 只在显式启用时为最多 500 个节点启动独立临时 Mihomo worker，最多 8 个并发；每个 worker 使用整数 loopback `mixed-port`、独立 `bind-address`、loopback controller、独立 256-bit secret 和 `Authorization: Bearer`。固定目标为 `https://www.gstatic.com/generate_204`，不做端口扫描或任意目标探测。
5. `aggregator.pipeline` 做规范化、来源标记、去重、过滤、数量上限与 shrink guard，然后在主动探测时按逐节点结果计算 `verified`、`stable`、`fast` 并筛选最终发布集合，再构建 manifest/health。
6. `aggregator.outputs` 生成本机 Clash 单文件配置、provider 辅助文件和 sing-box 映射。`dist/clash/config.yaml` 自带 `proxies` 与 `select`、`url-test`、`fallback` 三类组，不依赖相对 provider；本仓库不托管这些产物。

## 主动探测语义

- 默认 `active_probe=false`。普通运行、离线测试和未传 `--probe` 的命令不连接节点。
- `verified` 是严格的 3/3 轮成功；`stable` 是至少 3 轮且成功率至少 2/3；`fast` 仅表示延迟标签（平均延迟不超过 800ms），不替代成功率，也不降低 `stable` 发布要求。
- 每个探测行保留成功轮数、总轮数、成功率、平均/p95 延迟和错误类别。代码硬上限为最多 500 个节点、3 轮、8 并发、单次 timeout 上限 30 秒；超出节点数/并发数的 pipeline 参数或 runner 回报以 `probe_parameters_over_budget` fail-closed，预算以内但未进入本轮的候选记为 `not_tested_budget`。进程提前退出、controller 超时/认证/HTTP 错误和网络错误均使用有限枚举，worker 异常不会中止其他节点。
- `failed_probe` 表示没有成功轮次，`below_quality_threshold` 表示有成功但未达到最低等级，其他候选可能是未测。未实测不等于可用；发布 job 使用 `--probe-min-verdict stable`，失败/不完整/无合格节点时失败并保留 LKG。
- 结果受 runner 地域、出口网络、目标站点和上游限速影响，只能证明当前 runner 到固定目标的观测，不能推导全球或其他站点可用。
- 本地验证默认不运行真实节点 probe；可用本机已安装的 Mihomo 对合成配置做进程/controller smoke test。需要按本机网络验证公开候选时，运行 `scripts/local-refresh.ps1`，它使用本机 Clash Verge Rev Mihomo，生成被 Git 忽略的 `dist-local/` 与 `state-local/`，不修改 Clash Verge 配置、不发布 Pages。真实结果只代表本机当前网络；若存在 Mihomo/Wintun/TUN，探测流量可能经过现有隧道。公开候选无法取得时不发布未测节点。

## 发布边界

- 公开产物只接收 `public` 来源中 `enabled=true`、`publish=true`、`requires_review=false` 的节点。
- `private` 节点只允许通过显式本机参数生成到 `dist-private/`（或调用者指定的本地目录），默认被 `.gitignore` 忽略；私有凭据与私有正文通过环境变量或本机目录注入，不进入公开 `dist`。
- 公开仓库包含代码、文档、合成测试数据和 `config/sources.yaml` 中的公开来源清单；不包含真实节点内容、订阅令牌、节点凭据或私有来源正文。
- GitHub Actions 在 Pull Request 上只运行离线测试、编译和 workflow 结构检查；schedule 每 6 小时运行一次，workflow_dispatch 默认不发布。
- 发布 job 只在 `main`、非 fork、公开再分发授权闸门满足且允许发布的事件下运行；它强制 `--no-private`，只处理当前 3 个公开来源。3 个来源都必须抓取/解析为 `status=ok`，至少 2 个来源必须有 `accepted>0`，且 `manifest.counts.published>0`；单个来源为空时保留 manifest/health 的 drops 并写入脱敏 Step Summary，缺字段节点不会进入产物。
- 发布 job 继续明确传入 `--probe --probe-max-nodes 30 --probe-rounds 3 --probe-timeout 10 --probe-concurrency 4 --probe-min-verdict stable --require-core --no-private`，CI 的 30/4 不因本机硬上限提升而改变。每个逐节点探测结果参与质量计数、排序和最终筛选；预算外、探测失败、质量不足分别留在脱敏计数中。
- 发布权限为 `contents: read`、`pages: write`、`id-token: write`；Pages artifact 只上传 `pages/dist`，部署后还会检查固定 URL 的 HTTP 状态、Content-Type、大小、YAML 顶层结构和 `proxies` 数量。
- 代码许可证不授予订阅节点数据的使用或再分发权；未来公开数据需要独立授权及条款核对。

## 失败处理

- 空结果、所有公开来源失败、最小数量不足或 shrink guard 命中时 fail-closed。
- 成功产物先写入同文件系统 staging，再原子替换 `dist`；随后用同样的临时目录更新 `state/last-known-good`。
- 任一发布或 LKG 提交写入失败时恢复旧目录并写入失败态 `health.json`；没有 LKG 时保留失败状态，不把空结果当成功。
- source cache、manifest 和 health 都通过临时文件加 `os.replace` 写入，避免半文件。
- 主动探测失败时沿用同一 fail-closed/LKG 路径；单节点失败只进入脱敏分类计数，全部节点没有合格结果时才回退；LKG 只用于回退，不把上一轮结果冒充本轮探测通过。

## 证据边界

来源的 `publicly_offered` 只表示本机接入配置中的来源标记，不等于节点数据可合法再分发。仓库代码许可证与订阅节点、账号、域名、来源数据的使用/再分发条款是不同问题，接入者必须单独核对。公开发布由 `PUBLIC_NODE_REDISTRIBUTION_APPROVED` 闸门和工作流条件共同约束；本地语法校验、单元测试和在线 HTTP 结构检查都不证明节点可用，也不代替数据发布授权。

安全控制器 secret 只在 worker 生命周期内用于本地 Mihomo controller 认证，不写入 manifest、health、日志或报告。manifest、health 和 workflow 摘要只写总数与 `error_category`，不写节点正文、endpoint、UUID、密码或命令输出。DNS 校验结果随后由 `curl --resolve` 使用；这关闭了 hostname 二次解析路径，但本项目不宣称消除操作系统解析到连接之间的全部 TOCTOU 窗口，该项作为低风险残余保留。
