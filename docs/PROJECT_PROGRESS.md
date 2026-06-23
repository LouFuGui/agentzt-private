# AgentZT 项目进度与对话上下文

本文件用于记录关键对话结论、阶段决策与当前进度，帮助后续会话接续工作。每轮涉及范围、决策或状态变化时，应在此补充一条记录。

## 当前总参考

- 总项目计划书：`docs/AGENTZT_PRIVATE_ENTERPRISE_PLAN.md`
- 当前主线：先完成 Milestone 1（企业策略模型），再进入 Milestone 2（DeepSeek Provider Gateway）。

## 2026-06-23

### 已确认决策

- 对“策略存储接口化”收尾方案的确认：
  1. 同意新增 `PolicyStore` 存储接口，并提供首版 `JsonPolicyStore` 实现。
  2. 本阶段仅封装 policy 存储；`agents.json` registry 暂不纳入同一 store 抽象。
  3. 第一阶段收尾后，按计划进入 Milestone 2（DeepSeek Provider 接入主网关路径）。

### 当前实施记录

- 已将“AgentZT 私有化云原生企业版落地计划书 v0.1”整理为仓库文档。
- 正在补齐 Milestone 1 的唯一缺口：JSON 策略存储接口化。
- 策略存储接口化保持现有 `loadPolicy()` / `savePolicy()` 调用方式不变，避免扩大改动范围。

### 下一步

- 完成 `PolicyStore` / `JsonPolicyStore` 实现与测试。
- 运行 `npm test` 和 `npm run typecheck`。
- 如 Milestone 1 收尾通过，下一阶段开始前需确认 DeepSeek Provider 的公网/内网 `baseUrl` 配置形态与模型路由规则。

### Milestone 2 启动

- 用户确认第一阶段结束后可按计划书 §9 顺序进入 Milestone 2：DeepSeek Provider 接入主网关路径。
- 本轮目标：
  - 保持 mock 模式离线可用。
  - 在主 `callModel` 路径接入 provider routing。
  - 支持 `deepseek-*` 模型路由到 DeepSeek-compatible `/chat/completions`。
  - 支持默认公网 DeepSeek API 与可配置内网 DeepSeek-compatible `baseUrl`。
  - API Key 仍只由 gateway 侧从 env/Vault 读取，agent 侧不持有模型密钥。

### Milestone 2 续开发

- 已验证当前主 `callModel` 路径具备 provider routing、DeepSeek-compatible `/chat/completions` 转发、mock 离线模式和 Vault/env 网关侧密钥读取。
- 本轮补强方向：
  - 在 upstream response 与审计 meta 中记录实际 provider，方便确认 `deepseek-*` 是否命中 DeepSeek provider。
  - provider route 指向未配置 provider 时 fail closed，返回 `upstream_misconfigured`，避免静默回退到 Anthropic。
  - 补充 mock 离线、未知 provider、DeepSeek 自定义 `baseUrl` 的测试覆盖。

### Milestone 2 续开发补强

- 保留 upstream provider misconfiguration 的 provider metadata：当已解析 provider 但缺少对应企业 API key 时，`callModel()` 的 502 响应也会携带 `provider`，便于审计链确认命中的 provider。
- 修复 Direct Model Access `/v1/chat/completions` 对 upstream 失败的处理：DeepSeek/provider misconfiguration 等非 200 响应现在会原样以对应 HTTP status 返回，不再包装为空的 OpenAI 成功响应。
- 新增覆盖：
  - upstream 已选中 provider 但缺少 key 时返回 `upstream_misconfigured` 并保留 provider。
  - Direct Model Access 遇到未知 provider route 时 fail closed 返回 502。

### Milestone 2 Provider 抽象补强

- 将 upstream passthrough 的 Anthropic/DeepSeek 转发逻辑收敛到 `UpstreamProvider` adapter 抽象，主 `passthroughModel()` 只负责路由解析、密钥读取与 provider 委派。
- 当前 provider adapter 覆盖：
  - `AnthropicProvider`：继续转发到 `/v1/messages`，使用 gateway 侧企业 API key。
  - `DeepSeekProvider`：继续转发到 DeepSeek-compatible `/chat/completions`，并按调用协议保留 OpenAI raw response 或转换为 Anthropic message。
- 新增 Anthropic 自定义 provider/baseUrl 委派测试，确保后续新增 provider 时可沿同一 adapter 模式扩展。

### Milestone 2 完成度评估与 Milestone 3 启动

- 对照计划书 §8，Milestone 2 的目标与交付已覆盖：
  - DeepSeek model 转发、公网/内网 `baseUrl`、provider 配置、mock 模式保持可用。
  - provider abstraction、DeepSeek provider、routing config、相关测试均已落入主 gateway 路径。
- 已进入 Milestone 3（管理 API）最小闭环：
  - 复用本地账号 session 鉴权与角色层级，新增企业管理 REST API。
  - 覆盖 Project、Agent、Role、Policy、Audit 的首批管理路由。
  - Project 目前对应 enterprise governance `projectIds`；Agent 管理不暴露 `publicKeyJwk`，避免泄漏注册公钥细节之外的密钥材料。
- 本轮基线验证：变更前 `npm test` 通过 280 tests，`npm run typecheck` 通过。

### Milestone 3 管理 API 续推进

- 本轮继续补强管理 API 的 REST 与认证基础：
  - 企业管理路由新增 `/api/v1/...` 版本路径别名，与管理 API 设计规范中的 v1 路径约定对齐。
  - 管理 API 的 `x-user-id` / `x-user-role` 测试头仅在未配置 session token service 的测试环境生效；真实 gateway 启动后必须使用有效 session token。
  - 新增覆盖 `/api/v1/projects` 与真实 session service 存在时忽略测试头的测试用例。
- 本轮基线验证：变更前 `npm test` 通过 284 tests，`npm run typecheck` 通过。
