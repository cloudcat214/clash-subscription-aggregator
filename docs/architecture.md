# 聚合器架构与安全边界

## 数据流

1. 仓库将公开来源清单 `config/sources.yaml` 入库，其中包含公开来源 URL、来源元数据和 `private` 来源的环境变量占位；不含订阅令牌、节点凭据或私有正文。配置将 `public` 与 `private` 来源分开；Pull Request CI 只运行合成数据的离线测试，受门禁的定时/手动发布才运行来源聚合。
2. `aggregator.fetch` 只允许显式信任的 HTTPS host。每一跳 redirect 都重新解析、校验 host/IP 并用 `curl --resolve` 固定地址；`198.18.0.0/15` 只对配置中明确列出的 host 与地址生效。
3. `aggregator.parsing` 解析 Clash YAML/JSON、Base64 和 URI，保留协议的传输、TLS、Reality、插件等结构；不做节点拨测。
4. `aggregator.pipeline` 做规范化、来源标记、去重、过滤、数量上限与 shrink guard，然后构建 manifest/health。
5. `aggregator.outputs` 生成本机 Clash 单文件配置、provider 辅助文件和 sing-box 映射。`dist/clash/config.yaml` 自带 `proxies` 与 `select`、`url-test`、`fallback` 三类组，不依赖相对 provider；本仓库不托管这些产物。

## 发布边界

- 公开产物只接收 `public` 来源中 `enabled=true`、`publish=true`、`requires_review=false` 的节点。
- `private` 节点只允许通过显式本机参数生成到 `dist-private/`（或调用者指定的本地目录），默认被 `.gitignore` 忽略；私有凭据与私有正文通过环境变量或本机目录注入，不进入公开 `dist`。
- 公开仓库包含代码、文档、合成测试数据和 `config/sources.yaml` 中的公开来源清单；不包含真实节点内容、订阅令牌、节点凭据或私有来源正文。
- GitHub Actions 在 Pull Request 上只运行离线测试、编译和 workflow 结构检查；schedule 每 6 小时运行一次，workflow_dispatch 默认不发布。
- 发布 job 只在 `main`、非 fork、公开再分发授权闸门满足且允许发布的事件下运行；它强制 `--no-private`，只处理当前 3 个公开来源。3 个来源都必须抓取/解析为 `status=ok`，至少 2 个来源必须有 `accepted>0`，且 `manifest.counts.published>0`；单个来源为空时保留 manifest/health 的 drops 并写入脱敏 Step Summary，缺字段节点不会进入产物。
- 发布权限为 `contents: read`、`pages: write`、`id-token: write`；Pages artifact 只上传 `pages/dist`，部署后还会检查固定 URL 的 HTTP 状态、Content-Type、大小、YAML 顶层结构和 `proxies` 数量。
- 代码许可证不授予订阅节点数据的使用或再分发权；未来公开数据需要独立授权及条款核对。

## 失败处理

- 空结果、所有公开来源失败、最小数量不足或 shrink guard 命中时 fail-closed。
- 成功产物先写入同文件系统 staging，再原子替换 `dist`；随后用同样的临时目录更新 `state/last-known-good`。
- 任一发布或 LKG 提交写入失败时恢复旧目录并写入失败态 `health.json`；没有 LKG 时保留失败状态，不把空结果当成功。
- source cache、manifest 和 health 都通过临时文件加 `os.replace` 写入，避免半文件。

## 证据边界

来源的 `publicly_offered` 只表示本机接入配置中的来源标记，不等于节点数据可合法再分发。仓库代码许可证与订阅节点、账号、域名、来源数据的使用/再分发条款是不同问题，接入者必须单独核对。公开发布由 `PUBLIC_NODE_REDISTRIBUTION_APPROVED` 闸门和工作流条件共同约束；本地语法校验、单元测试和在线 HTTP 结构检查都不证明节点可用，也不代替数据发布授权。
