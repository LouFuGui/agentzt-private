# AgentZT 私有化云原生企业版落地计划书 v0.1

## 1. 项目定位

AgentZT 企业版定位为：面向企业私有化部署的 AI Agent 零信任访问控制平台。

首个落地重点不是“通用 AI 平台”，而是先把 Agent 访问 LLM 的身份、权限、审计、策略、网关控制做扎实。

目标能力：

- 企业可统一管理 Agent 身份
- Agent 访问模型必须经过 Gateway
- 按组织、项目、角色控制模型访问权限
- 支持 DeepSeek 作为首版模型 Provider
- 支持公网模型 API 与内网私有模型
- 支持本地账号 + API Key 管理
- 支持本地 hash chain 审计与导出
- 支持离线私有化部署
- 后续演进到完整云原生平台

## 2. 首版产品边界

首版必须有：

- Agent 身份管理
- 项目空间管理
- 角色与模型权限管理
- DeepSeek Provider 接入
- Gateway 模型访问控制
- 本地账号 + API Key
- 审计日志查看与导出
- 最小 Web 控制台
- 离线部署能力
- JSON 策略存储接口化

首版暂不做：

- 多组织 SaaS 租户计费
- 完整 SSO/OIDC
- SIEM/Syslog/WORM
- 完整 MCP 工具市场
- 多云 KMS/HSM 深度集成
- 复杂工作流编排
- 大规模分布式数据库依赖

## 3. 总体架构

目标架构：

### agentzt-client

- 部署在 Agent 所在环境
- 负责 Agent 身份证明、token 获取、请求转发

### agentzt-gateway

- 核心 PDP + PEP
- 负责认证、授权、模型转发、审计、guardrails

### 管理 API

- 管理 Agent、Project、Role、Policy、Audit

### 最小 Web 控制台

- Agent 列表
- 项目列表
- 策略配置
- 审计查看

### 配置与策略存储

- 首版 JSON
- 通过 storage interface 封装
- 后续可换 SQLite/PostgreSQL

### 私有化部署

- 离线包
- Docker / Kubernetes manifests 后续补齐
- 不强依赖外部服务

## 4. 企业策略模型设计

### 4.1 Organization

首版单组织，但数据模型预留：

- orgId
- name
- description
- createdAt
- updatedAt

默认：

- orgId: `default`

### 4.2 Project

项目由管理员自定义，可代表业务系统、部门或 Agent 团队。

字段：

- projectId
- orgId
- name
- description
- owner
- env
- status
- createdAt
- updatedAt

### 4.3 Agent

字段：

- agentId
- orgId
- projectId
- role
- description
- owner
- env: dev / test / prod
- status: active / disabled / revoked
- publicKey
- createdAt
- updatedAt

策略要求：

- disabled：拒绝所有新请求
- revoked：拒绝所有请求，并作为安全事件审计
- prod Agent 默认更严格审计

### 4.4 Role

字段：

- roleId
- orgId
- projectId 可选
- description
- models
- tools
- limits
- allowedHoursUTC
- jit
- status

### 4.5 Model Permission

首版采用 model 级别权限。

示例：

- deepseek-chat
- deepseek-coder
- internal-qwen-32b
- internal-llama-70b

后续可扩展为：

- provider
- model
- endpoint/action
- region
- data classification

## 5. DeepSeek Provider 首版方案

首版 Provider：

- DeepSeek

需要支持两种模式：

### 公网 DeepSeek API

- 企业出口代理可访问
- API Key 只在 gateway 侧保存

### 内网 DeepSeek-compatible endpoint

- 支持配置 baseUrl
- 兼容 OpenAI-style chat completions 更佳

设计方向：

- 增加 model provider 抽象
- gateway 根据请求 model 映射到 provider
- provider 层负责协议转换、鉴权、转发
- 保持 agent 侧无模型密钥

## 6. 审计设计

首版：

- 继续使用 JSONL hash chain
- 每条记录包含：
  - requestId
  - orgId
  - projectId
  - agentId
  - role
  - provider
  - model
  - action
  - decision
  - reason
  - latencyMs
  - timestamp
- 支持 CLI/API 导出
- 支持按 agent/project/model/decision 查询

后续：

- Syslog
- SIEM
- WORM
- 对象存储归档

## 7. 最小控制台范围

首版控制台只做：

- 登录
- Agent 管理
- Project 管理
- Role/Policy 查看与编辑
- Audit 查看与导出

不做复杂仪表盘，不做计费，不做多租户 SaaS 管理。

## 8. 开发里程碑

### Milestone 1：企业策略模型

目标：

- 引入 org/project/agent/status/env 概念
- 扩展 policy schema
- 抽象策略存储接口
- 保持现有 demo/test 尽量兼容

交付：

- enterprise policy types
- JSON policy store
- identity-store 扩展
- policy-engine 扩展
- tests

### Milestone 2：DeepSeek Provider Gateway

目标：

- 支持 DeepSeek model 转发
- 支持公网与内网 baseUrl
- 支持 provider 配置
- 保持 mock 模式可用

交付：

- provider abstraction
- deepseek provider
- routing config
- tests

### Milestone 3：管理 API

目标：

- 管理 Project、Agent、Role、Policy、Audit
- 本地账号 + API Key

交付：

- REST API
- auth middleware
- tests

### Milestone 4：最小 Web 控制台

目标：

- 管理 Agent、策略、审计

交付：

- simple console
- login
- CRUD screens

### Milestone 5：离线私有化部署

目标：

- 可打包、可离线安装、可部署到企业内网

交付：

- Dockerfile
- compose
- Kubernetes manifests
- offline deployment docs

## 9. 第一阶段建议开发顺序

建议先开发 Milestone 1，因为它是后续所有企业能力的基础：

- 定义 enterprise policy schema
- 增加 orgId/projectId/env/status
- 扩展 agent registry
- 扩展 policy engine
- 增加 JSON policy store interface
- 保持旧 `config/policy.json` 向后兼容
- 增加测试
- 更新文档
