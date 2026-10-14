# Clash/Mihomo 订阅超级聚合器

这是一个 Python 3.11+ 的最小聚合器：抓取配置中明确允许的公开来源，解析 Base64、URI、Clash YAML/JSON，规范化、去重、过滤后生成 Clash/Mihomo 与 sing-box 配置。节点级主动拨测默认关闭，解析成功不代表节点可用。

此公开仓库包含项目代码、文档、合成测试数据，以及 `config/sources.yaml` 中的公开来源清单（公开 URL、来源元数据和发布开关）。该文件不含订阅令牌、节点凭据或私有正文；`sources.private` 通过环境变量或本机目录注入，仅用于本机处理，不进入公开 `dist`。GitHub Actions 在 Pull Request 上只执行离线检查；定时和手动发布都经过公开再分发授权闸门，只处理当前清单中的公开来源。

## 订阅地址

- **主订阅（云端自动）**：`https://cloudcat214.github.io/clash-subscription-aggregator/dist/clash/config.yaml`。由 GitHub Actions 云端采集、主动测评并发布，电脑关机不影响。GitHub schedule 只代表触发请求，实际触发时间受 GitHub 调度影响，不是准点 15 分钟 SLA。
- **同源兼容镜像**：`https://cloudcat214.github.io/clash-subscription-aggregator/auto/clash/config.yaml`。与主订阅是同一份云端产物（同源镜像），保留供已有 /auto 使用者继续使用。

两条地址都可以直接粘贴到 Clash Verge Rev，指向同一份云端产物。

### 导入成功不等于节点可用

订阅返回 HTTP 200、YAML 可解析，只能证明配置文件能下载和读取，不能证明代理节点能连接。Clash Verge Rev 中节点显示红色 `Error`，表示该节点在当前客户端、内核和网络环境下连接或测速失败；这不是订阅导入失败，也不能靠换一个同源订阅 URL 修复。

云端主动测评运行在 GitHub Runner 上，测到的是 Runner 出口到节点的连通性，不等于你本机网络的连通性。2026-10-14 的一次对照样本中，Runner 与本机直连通过率差异很大（该样本只说明环境错位，不代表固定成功率）。因此 `published` 是发布节点数量，不是你本机可用数量；最终以你所用 Clash 内核对节点的实际连接结果为准。当前尚未把本机网络测试接入云端发布门槛。

`state/verified-pool*.json` 仅为运行时临时状态，不公开发布；历史公开版本可能仍保留旧池内容。本说明只停止后续提交，不改写既有 Git 历史。

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

### 节点主动探测与质量口径

- `settings.active_probe` 默认是 `false`；普通本地运行不会主动连接节点。只有显式传入 `--probe` 才启用主动探测。
- `--probe-backend spawn` 是默认兼容后端，硬上限为 500 个节点、3 轮、30 秒 timeout、8 并发；`--probe-backend delay` 是直连后端，硬上限放宽到 2000 个节点、3 轮、30 秒 timeout、16 并发。本机传入 `--probe-interface` 绑定物理网卡；云端留空时由系统自动选网卡。超出对应后端上限会以 `probe_parameters_over_budget` fail-closed。
- `delay` 后端先用临时 Mihomo、`MATCH,DIRECT` 和 mixed-port 请求 `http://www.baidu.com` 做控制测试；控制失败直接以 `probe_direct_control_failed` 中止。通过后按每批最多 400 个节点调用 controller `/proxies/{id}/delay`：第一阶段使用 6000ms，第二阶段对第一阶段通过者使用 8000ms、最多 3 轮，至少 2/3 成功才算 `stable`。
- 每个节点保留独立的轮次结果、成功率、平均延迟、p95 延迟和错误分类。`verified` 只表示 3/3 轮成功；`stable` 表示至少 3 轮且成功率至少 2/3；`fast` 只是延迟标签（平均延迟不超过 800ms），不单独放宽 `stable` 发布门槛。
- 只有达到发布配置的最低等级（发布 workflow 为 `stable`）的节点才进入最终产物。预算外节点记为 `not_tested_budget`，探测失败与成功率不足分别记为 `failed_probe`、`below_quality_threshold`；未实测不等于可用。
- `spawn` 与 `delay` 后端探测目标固定为 `https://www.gstatic.com/generate_204`，与客户端默认 `url-test` 和健康检查目标一致；结果只代表执行本轮的机器到目标的路径，受区域、出口网络、上游限速和目标站点策略影响，不代表全球或其他站点可用。
- 每个临时 worker 的 Mihomo 配置使用整数 `mixed-port`，并单独设置 `bind-address: 127.0.0.1`；这是 Mihomo 1.19.x 的兼容形状。controller readiness 会区分 `process_exit`、`controller_timeout`、`controller_auth_error`、`controller_http_error` 等有限分类。
- 单个 worker 异常只计入该节点的 `error_category` 并继续其他节点；只有没有合格结果时才 fail-closed 并优先恢复 LKG。manifest、health 和 workflow 摘要只保留质量总数及分类计数，不写节点内容、endpoint、UUID、密码、stdout 或 stderr。
- 本地回归使用 fake Mihomo/网络夹具；本轮另用本机 Clash Verge Rev Mihomo v1.19.32 对合成节点做了真实进程 smoke test。公开候选因来源加载受阻未取得可测试节点，未将该结果冒充真实节点可用性。
- 探测失败、结果不完整、无合格节点或写入失败都会 fail-closed，并优先保留 `state/last-known-good/`。LKG 是上一份可回退产物，不是本轮节点可用性证明。
- 每个临时 Mihomo worker 使用独立 loopback controller 和独立的 256-bit 随机 secret；secret 仅在 worker 生命周期内用于 `Authorization: Bearer`，不进入 manifest、health、日志或报告，worker 结束后随临时目录清理。

### 云端生产链与可逆回退

GitHub Runner 的网络出口不等于用户本机网络。生产链为单条云端链：GitHub Actions 按 `fetch` → Runner 使用 Mihomo delay 后端实测 → 发布 `docs/dist/`，并把同一份产物镜像到 `docs/auto/`（同源）。本机刷新脚本保留为可逆回退通道，不是正常依赖；启用回退时它使用独立的 `state/verified-pool.json` 池，与云端池 `state/verified-pool-auto.json` 互不共享。

手动刷新（默认只更新本机目录，不发布）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/refresh-publish.ps1
# 冒烟或小批量复核：
powershell -ExecutionPolicy Bypass -File scripts/refresh-publish.ps1 -MaxNodes 250
```

发布到 GitHub Pages：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/refresh-publish.ps1 -Publish
```

脚本默认定位 `D:\Program Files\Clash Verge\verge-mihomo.exe`，找不到时再尝试 `C:\Program Files\Clash Verge\verge-mihomo.exe`，也可用 `-Core` 指定。未传 `-ProbeInterface` 时自动排除 Meta/Tunnel/Wintun/TAP/VPN 后选择物理网卡，并打印检测结果；`-MinStable` 默认 5，`-MaxNodes` 默认 1500，输出和状态目录默认是 `dist-local/`、`state-local/`，已验证节点池默认是 `state/verified-pool.json`，也可用 `-VerifiedPool` 或 CLI 的 `--verified-pool` 改路径。启用主动探测时，池内节点先复检，剩余预算按来源轮询新候选；单次失败保留，连续两次失败才移出，发布集取池内当前有效节点。上轮发布达到 10 个节点时，拟发布集低于上轮 50% 会触发防抖并保留旧产物。每次过程写入 `reports/refresh-<时间戳>.log`，只记录脱敏计数和流程状态，不写节点凭据。

本机产物仍可直接导入 Clash Verge Rev：`dist-local/clash/config.yaml`。公开订阅地址见上方“订阅地址”一节。

建议在 Verge 中为该订阅设置自动更新间隔（例如 1–6 小时），并保留手动刷新入口以便在网络环境变化时立即复核。本项目不读取密钥、不修改系统代理、不启停或修改用户 Clash Verge 配置。

公开 Pages 内容可能包含来源公开提供的节点连接信息；代码仓库采用 MIT License 不等于节点数据、订阅源、域名或账号获得了再分发授权。接入者必须单独核对来源条款。结果还受区域、执行时点、出口线路、上游限速和免费节点寿命影响，节点在下一轮可能失效，固定 URL 不是永久可用性保证。

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
- `sources.private` 默认不发布。需要本机混合验证时显式使用 `--include-private --private-output dist-private`；私有产物只落在本机目录，已加入 `.gitignore`。云端工作流始终使用 `--no-private`。
- 公开节点产物可能包含来源本身提供的连接凭据，这是公开订阅内容的一部分；程序、日志和报告不打印节点 URI、UUID、密码或完整敏感载荷。
- 来源抓取只允许使用者配置的 HTTPS host。受控 fake-IP 例外仅允许 `trust_hosts` 中的主机落入 `198.18.0.0/15`；当前信任主机为 `raw.githubusercontent.com`、`www.gitlabip.xyz`、`gitlab.com`。`settings.controlled_proxy_addresses` 保留为兼容配置但不再逐个限制轮换地址；非信任主机仍拒绝该网段。该项是针对本机 fake-IP DNS 的受控收窄放宽：通过 `curl --resolve` 固定已校验地址，但不能借此放行其他主机。IPv4-mapped IPv6（`::ffff:a.b.c.d`）先解包为 IPv4 再走同一拒绝逻辑；常见 NAT64 `64:ff9b::/96` 与 `64:ff9b:1::/48` 显式拒绝。`100.64.0.0/10`、文档/基准测试地址、私网、回环、metadata 和链路本地地址拒绝。每一跳 redirect 都重新校验。
- 当前实现接受“解析校验后用 `curl --resolve` 固定地址”的跨平台折中：它避免再次按 hostname 解析，但不宣称消除操作系统解析到连接之间的全部 TOCTOU 窗口。该项保留为低风险残余，不以文档或测试伪装成已解决。

## 接入新的授权订阅源

本聚合器只接受拥有或明确授权、允许自动抓取的公开订阅源。以下链接一律不接受：来源不明、需要登录、付费、受限，以及需要绕过访问控制才能获取的链接。

接入方式是在 `config/sources.yaml` 的 `sources.public` 增加条目，至少填写 `id`、`name`、`url`、`format`、`enabled`、`publish`、`requires_review`、`authorized`，并建议同时填写 `license`、`license_evidence` 与备注 `note`；如果来源 host 不在 `settings.allowed_source_hosts` 中，需要一并加入。`authorized: true` 需人工复核后填写，未显式填写时按 `enabled && publish && !requires_review` 保守推导；该字段仅作登记与审计展示（会出现在 manifest 的 `sources[]`），不改变采集与发布开关的实际行为。条目提交到 `main` 后，云端工作流会在下一轮自动采集。

当前支持的输入格式：Clash/Mihomo YAML、Base64、JSON、一 URI 一行、sing-box outbounds；URI scheme 支持 `vmess`、`vless`、`trojan`、`ss`、`ssr`、`hysteria`、`hysteria2`、`tuic`，以及标准 `http`/`https`/`socks5`/`socks5h`。

## 输出目录

直接运行 `aggregator run` 时，下面的 `dist/` 是默认输出目录；`refresh-publish.ps1` 使用被忽略的 `dist-local/`；公开 Pages 上的 `docs/dist/` 与 `docs/auto/` 由云端工作流发布（`docs/auto/` 为 `docs/dist/` 的同源镜像）。

| 文件 | 用途 |
|---|---|
| `dist/clash/config.yaml` | Clash Verge Rev 本机导入主文件，自包含 `proxies`，并内含 `select`、`url-test`、`fallback` 三类组 |
| `dist/clash/providers/aggregate.yaml` | 本地调试或需要 file provider 时使用的节点文件 |
| `dist/clash/config-provider.yaml` | 仅在传入 `--base-url` 时生成的绝对 URL provider 辅助配置 |
| `dist/sing-box/config.json` | 能明确映射的 sing-box outbounds；无法安全映射的协议会计入 dropped，不伪装成可用配置 |
| `dist/manifest.json` | 直接运行聚合器时的来源状态、节点数、协议数、dropped 统计、校验结果和 SHA256 |
| `dist/health.json` | 直接运行聚合器时的本轮状态、失败原因和 LKG 回退状态 |
| `docs/dist/clash/config.yaml` | 云端发布的公开订阅主文件（固定订阅地址指向此处） |
| `docs/auto/clash/config.yaml` | 与 `docs/dist/` 同源的兼容镜像 |

本地文件导入时选择 `dist-local/clash/config.yaml`（或直接运行聚合器产生的 `dist/clash/config.yaml`），不需要另行下载 provider 文件。公开发布成功后的固定导入地址见“订阅地址”一节；`dist/`、`state/`、`dist-local/`、`state-local/`、缓存和报告仍按各自用途处理，`docs/dist/` 与 `docs/auto/` 进入公开 Pages。

## GitHub Actions：离线检查与受门禁的公开发布

`.github/workflows/update.yml` 与 `.github/workflows/auto-refresh.yml` 的行为是：

- Pull Request 只运行 pytest、compileall 和 workflow 结构检查，不抓取来源、不生成发布产物、不部署 Pages；
- `main` 上 `docs/**` 的 push 或手动 `workflow_dispatch` 才进入部署 job；部署前只检查已提交的 `docs/dist/clash/config.yaml` 存在且 YAML 顶层结构可解析；
- `vars.PUBLIC_NODE_REDISTRIBUTION_APPROVED == 'true'` 仍是本机公开发布的总闸；`auto-refresh.yml` 使用 `--no-private`，只处理配置中的公开来源；
- `auto-refresh.yml` 每 15 分钟计划触发一次（实际触发时间受 GitHub 调度影响），也支持手动触发；它在 Ubuntu Runner 下载固定且校验过的 Mihomo、运行公开来源聚合与 delay 探测，把成功结果写入 `docs/dist/`（并镜像到 `docs/auto/`），并在同一工作流中部署 Pages。失败或结果不足时不覆盖旧产物；
- Pages artifact 路径是 `docs`，因此固定 URL 下的 `dist/clash/config.yaml` 与 `auto/clash/config.yaml` 以及各自的 manifest、health 保持同一目录结构。`/dist` 与 `/auto` 由云端同源产物维护；本机刷新通道只作为可逆回退保留，不是正常依赖。

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
