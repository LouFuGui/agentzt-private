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
