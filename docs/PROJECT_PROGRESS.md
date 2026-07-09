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

### Milestone 3 管理 API 收尾

- 本轮对照计划书 §8 中 Milestone 3 交付继续补齐管理 API：
  - Agent 管理新增管理员创建与删除路由；创建时校验 Ed25519 公钥、角色存在性、重复 agentId，并继续避免在响应中暴露 `publicKeyJwk`。
  - Audit 管理新增按 `agentId`、`projectId`、`model`/`resource`、`decision`、`role`、`action` 查询过滤，支撑计划书中按 agent/project/model/decision 查询审计的要求。
  - 新增对应管理 API 测试覆盖。
- 本轮基线验证：变更前 `npm test` 通过 286 tests，`npm run typecheck` 通过。
- 当前判断：Milestone 3 的 REST API、auth middleware、本地账号/API Key 基础与测试交付已形成可进入 Milestone 4（最小 Web 控制台）的闭环。

### Milestone 4 最小 Web 控制台启动

- 本轮进入 Milestone 4（最小 Web 控制台）并完成首个 dependency-free 控制台闭环：
  - Gateway 新增 `/console` 静态控制台入口，保持无构建步骤、无新增运行时依赖。
  - 控制台支持登录、Agent 管理、Project 管理、Role/Policy 查看编辑、Audit 查询查看。
  - 控制台复用 Milestone 3 的 `/api/auth/*` 与 `/api/v1/*` 管理 API，不新增独立后端状态。
- 本轮基线验证：安装依赖前 `npm test` 因 `vitest` 缺失失败、`npm run typecheck` 因 `@types/node` 缺失失败；`npm ci` 后 `npm test` 与 `npm run typecheck` 均通过。

### Milestone 4 收尾与 Milestone 5 启动

- 本轮继续推进并完成 Milestone 4（最小 Web 控制台）缺口：
  - Audit viewer 新增 JSON 导出按钮，覆盖“Audit 查看与导出”交付。
  - 控制台测试补充导出入口与浏览器下载实现的静态契约检查。
- 当前判断：Milestone 4 的 login、Agent/Project/Role/Policy 管理、Audit 查看与导出、静态 console 入口已达到计划书最小交付范围。
- 已进入 Milestone 5（离线私有化部署）最小交付：
  - 新增 dependency-locked `Dockerfile`，保持 Node 22 原生 TypeScript 运行、无构建步骤。
  - 新增 `compose.yml`，支持 gateway 与可选 client profile，挂载 `config/` 与 `.agentzt/`。
  - 新增 Kubernetes gateway ConfigMap、Deployment、Service、PVC 示例。
  - 新增 `docs/OFFLINE_DEPLOYMENT.md` 记录镜像导出、Compose、Kubernetes 离线部署流程。

### Milestone 5 离线部署续推进

- 本轮继续推进 Milestone 5 的可验证性与交接安全：
  - 新增 deployment artifact 静态测试，覆盖 Dockerfile dependency lock、Compose gateway/client 挂载、Kubernetes ConfigMap/Deployment/Service/PVC 与离线部署文档关键步骤。
  - `docs/OFFLINE_DEPLOYMENT.md` 补充转移前 preflight，明确导出前运行测试/typecheck，并提醒不要夹带本地 API keys、跨环境私钥或不应外流的审计日志。

### Milestone 5 完成度复核

- 对照总计划书 §8 的 Milestone 5 目标与交付，本轮判断已达到首版最小交付：
  - 可打包：`Dockerfile` 使用 lockfile 安装 runtime dependencies，并直接运行 Node 22 原生 TypeScript。
  - 可离线安装：文档覆盖在线构建/导出镜像、离线环境 `docker load` 导入与启动。
  - 可部署到企业内网：`compose.yml` 覆盖单机/内网 Compose，`deploy/kubernetes/` 覆盖集群 ConfigMap、Deployment、Service、PVC。
  - 交付物完整：Dockerfile、Compose、Kubernetes manifests、offline deployment docs 均已落地，并有 deployment 静态测试保护。
- 对照总计划书首版产品边界，Milestone 1-5 均已有最小闭环；后续如继续演进，应进入新的增强阶段，而不是 Milestone 5 的阻塞缺口。

## 2026-07-09

### 第二版计划书需求引导启动

- 用户确认第二版项目计划书希望更多围绕“智能体沙盒”方向推进，因为用户主要负责该方向。
- 用户当前已有可用的沙盒运行时 Docker，并且比较了解 AIOsandbox 与 opensandbox。
- 当前引导重点应从“AgentZT 如何把沙盒运行时纳入零信任控制面”继续收敛，包括沙盒接入位置、运行时抽象、权限模型、审计范围、网络/文件系统隔离、工具执行策略与首个可交付闭环。
- 用户确认第二版首阶段先做“5 + 1”：先接入现有 Docker 沙盒 runtime，跑通“创建沙盒 → 执行命令/代码 → 返回结果 → 审计”的最小闭环，同时优先覆盖 Agent 工具执行沙盒；之后再扩展到更全面的 Agent 运行沙盒和企业沙盒编排平台。
- 用户说明当前使用 AIOsandbox 和 opensandbox，并确认沙盒 runtime 接入方式应优先按 HTTP API 服务理解：AgentZT Gateway 通过 REST/HTTP adapter 调用外部沙盒服务，而不是直接 shell out 到 Docker CLI 或引入运行时依赖。
- 用户确认首版工具执行沙盒接口选择统一 `sandbox.execute`：同一接口内支持 `command` 与 `code` 两种最小执行请求，后续再扩展文件上传、长任务、会话复用等能力。
- 用户确认沙盒安全策略选择“全部都要，但分阶段做”：网络策略、文件系统策略、资源限制、命令/语言白名单与审计都应纳入第二版计划；首个开发闭环建议优先落地资源限制、完整审计与基础网络默认禁用。
- 用户确认首版 `sandbox.execute` 同时需要两个入口：管理 API 调试入口（例如 `/api/v1/sandbox/execute`）与 Agent 工具调用入口（例如 `/v1/tools/sandbox.execute`）；前者用于管理员/控制台调试，后者用于 Agent 通过 token 正式调用。
- 用户确认 `sandbox.execute` 权限控制选择“全部都要，分阶段做”：按 role、project、命令/语言与资源额度控制都应纳入第二版计划；首个开发闭环建议先做 role 是否允许 `sandbox.execute` 与资源上限，再扩展命令/语言白名单和 project 级策略。

### 智能体沙盒 MVP 开发启动

- 本轮用户再次强调“工具执行沙盒、Agent 运行沙盒、模型访问前后安全沙盒、企业沙盒编排平台”是主线，其中首要交付仍是最小闭环：只接入现有 Docker 沙盒 runtime，跑通“创建沙盒 → 执行命令/代码 → 返回结果 → 审计”。
- 首批实现聚焦 Agent 工具入口 `sandbox.execute`：通过 Gateway 既有 `/v1/tools/{name}` 路径进入 RBAC/ABAC/OPA/审计链，工具内部使用 Docker Engine HTTP API 创建一次性容器执行 command/code，默认禁用网络并施加超时与内存上限。
- 后续仍需补齐管理 API 调试入口、命令/语言白名单、project 级策略、长任务/会话复用、文件处理与 AIOsandbox/opensandbox 编排适配。

### 智能体沙盒 Runtime 抽象与策略补强

- 本轮按“实施计划”推进首批最小代码闭环：
  - 新增统一 `SandboxRuntime` adapter 抽象，现有 Docker 执行路径改为 `docker` runtime adapter。
  - 新增通用 HTTP sandbox runtime adapter，支持 `aiosandbox` / `opensandbox` / `http` 通过 `baseUrl + executePath` 接入外部沙盒服务，首版只覆盖 `execute` 能力。
  - `sandbox.execute` 继续作为 Agent 工具统一入口，并复用管理 API 调试入口 `/api/v1/sandbox/execute`。
  - Gateway sandbox 配置新增 `executePath`、`filesystemAccess` 与 `policy`，首批策略覆盖命令白名单、语言白名单、资源上限、网络开关，并保留后续 role/project 细粒度控制字段。
  - `tool.call` 审计 meta 扩展记录 sandbox runtime、sandboxId、policy decision、资源限制、网络 posture 与文件系统 posture。
- 新增/补强测试覆盖：
  - Docker runtime adapter 继续覆盖 create/start/wait/logs/remove 路径。
  - HTTP runtime adapter 覆盖 OpenSandbox/AIOsandbox-style execute 调用。
  - Agent 工具入口覆盖审计 meta。
  - sandbox policy 拒绝命令时不触发 runtime 执行。
- 本轮针对性验证：`npx vitest run tests/gateway/sandbox.test.ts tests/api/management.test.ts` 通过，`npm run typecheck` 通过。

### 智能体沙盒管理调试审计补齐

- 本轮继续推进 sandbox.execute 最小闭环的审计一致性：
  - 管理 API 调试入口 `/api/v1/sandbox/execute` 现在会将执行结果写入 gateway audit hash chain。
  - 审计记录复用 `tool.call` / `sandbox.execute` 资源维度，并标记 `authVia: management`、管理用户 ID、执行结果与 sandbox audit meta。
  - 补充管理 API 测试，验证管理员调试执行会落审计日志，便于后续控制台调试与 Agent 工具调用在同一审计视图中追踪。

### 智能体沙盒编排继续推进

- 当前状态判断：工具执行沙盒、管理调试入口、Docker/HTTP runtime adapter、命令/语言/project/资源策略与审计已经具备首版闭环；完整企业沙盒编排平台此前尚未全部实现。
- 本轮继续补齐下一层能力：
  - `SandboxRuntime` 扩展健康检查与 Agent process sandbox 生命周期 adapter：create/start/exec/stop/destroy。
  - Docker runtime 增加本地 Agent process sandbox 生命周期实现；HTTP runtime 增加 AIOsandbox/OpenSandbox 风格生命周期路径适配。
  - 管理 API 新增 `/api/v1/sandbox/runtimes` 健康/registry 调试入口，以及 `/api/v1/sandbox/agents` Agent 沙盒创建、启动、执行、停止、销毁入口。
  - 审计事件从单次 `tool.call` 扩展到 `sandbox.create`、`sandbox.start`、`sandbox.exec`、`sandbox.stop`、`sandbox.destroy`。
  - Gateway 模型调用路径新增可选 `sandbox.modelValidation`：在 guardrail 后、upstream 前对输入中的高风险代码/命令做 dry-run/语法验证；模型输出后也可二次验证并在失败时替换响应。
  - `config/gateway.json` 增加 runtime registry 示例、health/agent 路径与模型沙盒验证默认配置。
- 当前仍属于“控制面最小编排”而非完整平台：容量调度、长任务会话复用、文件工件、浏览器/Jupyter/MCP runtime 能力声明仍是后续增强方向。

### 智能体沙盒收敛补强

- 本轮对照“工具执行沙盒优先收敛、多 sandbox runtime、Agent 运行沙盒、模型访问前后安全沙盒、企业沙盒编排平台”复核后继续补齐：
  - AIO Sandbox 适配改为使用其公开 `/v1/*` API 约定，`sandbox.execute` 在 `aiosandbox` runtime 下会调用 `/v1/shell/exec`，Python code 调用 `/v1/jupyter/execute`。
  - OpenSandbox 适配新增 lifecycle-native `POST /v1/sandboxes`、`resume`、`pause`、`DELETE /v1/sandboxes/{id}` 路径，用于 Agent process sandbox 控制面管理。
  - Runtime registry 开始参与选择：按 enabled provider、runtime 类型/名称、project/role/capability 约束与 capacity 排序选择具体 runtime provider。
  - `sandbox.shell`、`sandbox.file.read`、`sandbox.file.write`、`sandbox.jupyter.execute` 逐步收敛到统一 `sandbox.execute` policy/runtime helper，不再绕过沙盒策略与统一审计 meta。
  - `config/gateway.json` 的 runtime registry 示例补充 AIO Sandbox/OpenSandbox API key env、capabilities、networkPolicy、filesystemPolicy 与 project 选择示例。
- 当前仍未宣称完成完整企业沙盒平台：OpenSandbox execd 流式 command/file/code、长任务会话复用、文件工件、浏览器/Jupyter/MCP runtime 能力声明与调度状态持久化仍可继续增强。
