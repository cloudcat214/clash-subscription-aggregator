# 聚合器架构与安全边界

## 数据流

1. 使用者自备本机 `config/sources.yaml`，将 `public` 与 `private` 来源分开；`config/` 不提交仓库。CI 只运行合成数据的离线测试，不运行来源聚合。
2. `aggregator.fetch` 只允许显式信任的 HTTPS host。每一跳 redirect 都重新解析、校验 host/IP 并用 `curl --resolve` 固定地址；`198.18.0.0/15` 只对配置中明确列出的 host 与地址生效。
3. `aggregator.parsing` 解析 Clash YAML/JSON、Base64 和 URI，保留协议的传输、TLS、Reality、插件等结构；不做节点拨测。
4. `aggregator.pipeline` 做规范化、来源标记、去重、过滤、数量上限与 shrink guard，然后构建 manifest/health。
5. `aggregator.outputs` 生成本机 Clash 单文件配置、provider 辅助文件和 sing-box 映射。`dist/clash/config.yaml` 自带 `proxies` 与 `select`、`url-test`、`fallback` 三类组，不依赖相对 provider；本仓库不托管这些产物。

## 发布边界

- 公开产物只接收 `public` 来源中 `enabled=true`、`publish=true`、`requires_review=false` 的节点。
- `private` 节点只允许通过显式本机参数生成到 `dist-private/`（或调用者指定的本地目录），默认被 `.gitignore` 忽略；所有运行产物及来源配置只保留本机。
- 公开仓库只含代码、文档和合成测试数据，没有真实节点、私有来源或订阅凭据。
- GitHub Actions 仅在 Pull Request 上运行离线测试与编译检查；无 push、schedule、workflow_dispatch 触发器，无节点发布 job 或 Pages 部署步骤。
- 工作流仅有源码读取权限，不读取或设置节点再分发授权变量，不启用 Pages，不上传产物。
- 代码许可证不授予订阅节点数据的使用或再分发权；未来公开数据需要独立授权及条款核对。

## 失败处理

- 空结果、所有公开来源失败、最小数量不足或 shrink guard 命中时 fail-closed。
- 成功产物先写入同文件系统 staging，再原子替换 `dist`；随后用同样的临时目录更新 `state/last-known-good`。
- 任一发布或 LKG 提交写入失败时恢复旧目录并写入失败态 `health.json`；没有 LKG 时保留失败状态，不把空结果当成功。
- source cache、manifest 和 health 都通过临时文件加 `os.replace` 写入，避免半文件。

## 证据边界

来源的 `publicly_offered` 只表示本机接入配置中的来源标记，不等于节点数据可合法再分发。仓库代码许可证与订阅节点、账号、域名、来源数据的使用/再分发条款是不同问题，接入者必须单独核对。本次只公开代码，不提供在线订阅，不启用 Pages；本地语法校验和单元测试不证明节点可用，也不代替数据发布授权。
