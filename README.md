# Clash/Mihomo 订阅超级聚合器

这是一个 Python 3.11+ 的最小聚合器：抓取配置中明确允许的公开来源，解析 Base64、URI、Clash YAML/JSON，规范化、去重、过滤后生成 Clash/Mihomo 与 sing-box 配置。节点级主动拨测默认关闭，解析成功不代表节点可用。

此公开仓库包含项目代码、文档、合成测试数据，以及 `config/sources.yaml` 中的公开来源清单（公开 URL、来源元数据和发布开关）。该文件不含订阅令牌、节点凭据或私有正文；`sources.private` 通过环境变量或本机目录注入，仅用于本机处理，不进入公开 `dist`。GitHub Actions 在 Pull Request 上只执行离线检查；定时和手动发布都经过公开再分发授权闸门，只处理当前清单中的公开来源。

## 本地运行

```powershell
python -m pip install -e ".[dev]"
python -m aggregator --help
python -m pytest -q
python -m compileall -q aggregator tests
python -m aggregator init-dist --output dist
# 使用仓库中的公开来源清单运行；如需自定义本机来源，可准备相应的 config/sources.yaml：
python -m aggregator run --config config/sources.yaml --output dist --state state --no-private
```

运行时只抓取使用者配置中已启用且获准使用的公开来源；`--offline` 只允许本地文件来源。仓库不提供可用订阅；测试中的 `example.invalid` 地址和占位 UUID/密码不可用于连接。没有有效公开节点时命令以非零状态退出，并保留 last-known-good，不把空配置冒充成功。

如需自定义本机配置，最小结构如下（没有来源，不能生成可用订阅）：

```yaml
version: 1
settings:
  active_probe: false
  allowed_source_hosts: []
  trust_hosts: []
sources:
  public: []
  private: []
```

仓库内的 `config/sources.yaml` 已列出公开来源及 HTTPS host 白名单；使用者如需替换或补充来源，必须确认已获授权。可参考 `tests/test_pipeline.py` 中的本地文件来源示例；测试只使用合成数据，不依赖仓库外的来源配置。

## 来源与隐私边界

- `sources.public` 只有 `enabled=true`、`publish=true`、`requires_review=false` 才能进入公开聚合。
- `sources.private` 默认不发布。需要本机混合验证时显式使用 `--include-private --private-output dist-private`；私有产物只落在本机目录，已加入 `.gitignore`。CI 不运行聚合器。
- 公开节点产物可能包含来源本身提供的连接凭据，这是公开订阅内容的一部分；程序、日志和报告不打印节点 URI、UUID、密码或完整敏感载荷。
- 来源抓取只允许使用者配置的 HTTPS host。受控解析例外必须同时匹配显式信任的 host 和精确地址，TLS 证书校验仍开启；其他内网、私网、回环和链路本地地址拒绝。每一跳 redirect 都重新校验。

## 本机输出（不提交仓库）

| 文件 | 用途 |
|---|---|
| `dist/clash/config.yaml` | Clash Verge Rev 本机导入主文件，自包含 `proxies`，并内含 `select`、`url-test`、`fallback` 三类组 |
| `dist/clash/providers/aggregate.yaml` | 本地调试或需要 file provider 时使用的节点文件 |
| `dist/clash/config-provider.yaml` | 仅在传入 `--base-url` 时生成的绝对 URL provider 辅助配置 |
| `dist/sing-box/config.json` | 能明确映射的 sing-box outbounds；无法安全映射的协议会计入 dropped，不伪装成可用配置 |
| `dist/manifest.json` | 来源状态、节点数、协议数、dropped 统计、校验结果和 SHA256 |
| `dist/health.json` | 本轮状态、失败原因和 LKG 回退状态 |

本地文件导入时选择 `dist/clash/config.yaml`，不需要另行下载 provider 文件。公开发布成功后，固定导入地址为 `https://cloudcat214.github.io/clash-subscription-aggregator/dist/clash/config.yaml`；所有本地 `dist/`、`state/`、缓存和报告仍只保留本机。

## GitHub Actions：离线检查与受门禁的公开发布

`.github/workflows/update.yml` 的行为是：

- Pull Request 只运行 pytest、compileall 和 workflow 结构检查，不抓取来源、不生成发布产物、不部署 Pages；
- 每 6 小时运行一次，也支持手动触发；手动输入 `publish_nodes` 默认关闭；
- 发布仅允许在 `main`、非 fork、公开再分发授权闸门开启且手动明确发布或定时触发时进行；
- 发布只读取 3 个当前已授权的 `sources.public` 来源，强制 `--no-private`，固定使用受摘要校验的 Mihomo 核心；3 个来源都必须抓取/解析为 `status=ok`，但允许单个来源 `accepted=0`，只要至少 2 个来源 `accepted>0` 且 `manifest.counts.published>0`。核心校验、产物结构和固定 URL HTTP/YAML 检查全部通过后才部署；空来源的 drop 原因只写入 manifest/health 和脱敏 Step Summary，不会把缺字段节点发布；
- Pages artifact 只包含 `pages/dist`，不包含仓库其他文件；Step Summary 只记录状态、发布数量、验证状态和固定导入地址，不输出节点正文或凭据。

公开节点数据仍需由接入者核对各来源节点数据的使用与再分发条款；代码仓库公开不等于节点数据公开授权，工作流闸门也不替代这项责任。

## 许可证与来源条款

本仓库代码采用 MIT License，见 `LICENSE`。这只针对本仓库代码，不自动授予任何订阅源、节点、域名、账号或来源数据的使用权。`publicly_offered: true` 只是接入者记录的来源属性，不是“可以合法再分发”的结论。来源仓库的代码 license 也不必然等于节点数据 license；公开部署前必须由接入者单独核对使用和 redistribution terms，未确认时不得声称 legal-to-redistribute。

## 故障回退

本机产物生成采用 staging 目录、原子替换和 `state/last-known-good/`：

1. 空结果、来源全失败、最小节点数不足、异常骤减或核心校验失败时拒绝发布；
2. 有 LKG 时恢复旧的 Clash、sing-box 和 manifest 核心文件；
3. 写入 `health.json` 标明 `failed` 与 `fallback=last-known-good`；
4. 没有 LKG 时保留失败态，不把 bootstrap 空配置当作可用订阅。

详见 [docs/architecture.md](docs/architecture.md)。
