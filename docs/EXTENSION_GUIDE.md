# AgentZT 生产级扩展技术方案

基于 AgentZT 零信任框架，结合 OpenSandbox/AIOsandbox 开发经验，提供完整的生产级扩展方案。

---

## 目录

1. [生产级加固方案](#1-生产级加固方案)
2. [沙盒集成架构](#2-沙盒集成架构)
3. [MCP 协议集成](#3-mcp-协议集成)
4. [LLM 智能路由](#4-llm-智能路由)
5. [智能体框架](#5-智能体框架)
6. [可视化控制台](#6-可视化控制台)
7. [部署架构](#7-部署架构)
8. [实施路线图](#8-实施路线图)

---

## 1. 生产级加固方案

### 1.1 密钥管理

```yaml
HSM/KMS 集成:
  AWS: AWS KMS + CloudHSM
  Azure: Azure Key Vault + HSM
  GCP: Cloud KMS
  自托管: HashiCorp Vault (推荐)

网关签名密钥:
  - 存储在 HSM/KMS 中
  - 支持自动轮换 (90天周期)
  - 审计所有密钥访问

Agent 密钥生命周期:
  - 密钥生成: 在安全环境 (HSM) 中生成
  - 分发: 通过安全通道 (mTLS) 分发
  - 吊销: 实时撤销 + 证书黑名单
  - 备份: 加密备份到独立存储
```

### 1.2 不可变审计存储

```
┌─────────────────────────────────────────────────────────────┐
│                    AgentZT Audit Pipeline                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  本地 JSONL (哈希链)  →  Kafka/Redis (缓冲)  →  归档存储    │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐
    │  S3/     │        │ Splunk/  │        │ WORM     │
    │  GCS     │        │ Elastic  │        │ Storage  │
    └──────────┘        └──────────┘        └──────────┘
```

### 1.3 网络安全

```yaml
入口层:
  - API Gateway (Kong/AWS API GW)
  - WAF (AWS WAF / Cloudflare)
  - DDoS 防护

内部通信:
  - 100% mTLS
  - 服务网格 (Istio/Linkerd)
  - 网络分段 (零信任微分段)

出口控制:
  - DNS 过滤
  - IP 白名单
  - 应用层代理
```

### 1.4 运行时安全

```yaml
基础设施:
  - eBPF 系统追踪 (Falco)
  - 进程树监控
  - 文件完整性监控

容器安全:
  - 非 root 运行
  - 只读文件系统
  - Seccomp 配置文件
  - AppArmor/SELinux

运行时保护:
  - 异常行为检测 (UEBA)
  - 实时告警
  - 自动响应剧本
```

### 1.5 弹性设计

```yaml
高可用:
  - 网关: 3+ 副本 (Kubernetes)
  - 状态存储: Redis Cluster
  - 审计存储: 多 AZ 复制

限流降级:
  - 速率限制 (滑动窗口)
  - 熔断器 (Circuit Breaker)
  - 优雅降级策略

灾备:
  - 定期密钥轮换
  - 跨区域复制
  - RTO < 5min, RPO < 1min
```

---

## 2. 沙盒集成架构

### 2.1 架构概览

基于 OpenSandbox/AIOsandbox 经验，设计多层沙盒隔离：

```
┌─────────────────────────────────────────────────────────────────┐
│                    AgentZT Security Layer                        │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│   │  RBAC 策略  │  │  审计日志  │  │   资源配额管理          │   │
│   └─────────────┘  └─────────────┘  └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Sandbox Orchestrator                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│   │ Web      │  │ Code     │  │ File     │  │ Process          │ │
│   │ Sandbox  │  │ Sandbox  │  │ Sandbox  │  │ Sandbox          │ │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐
    │ Puppeteer│        │ Docker/  │        │ Seccomp  │
    │ + Chrome │        │ Isolate  │        │ -bpf     │
    └──────────┘        └──────────┘        └──────────┘
```

### 2.2 Web 沙盒 (Chromium)

```typescript
// 核心功能
interface WebSandboxConfig {
  viewport?: { width: number; height: number };
  userAgent?: string;
  blockAds?: boolean;
  jsEnabled?: boolean;
  corsEnabled?: boolean;
}

// 已实现: src/gateway/sandbox.ts → WebSandbox
```

### 2.3 代码执行沙盒

```typescript
// 层级化执行策略
execution_levels = {
  level_1: {
    // Node.js vm 模块 (JS only)
    language: ['javascript'],
    timeout: 5000,
    memory: 128
  },
  level_2: {
    // Isolate (C/C++/Rust sandbox)
    language: ['python', 'javascript', 'bash'],
    timeout: 30000,
    memory: 256
  },
  level_3: {
    // Docker 容器 (完整环境)
    language: ['*'],
    timeout: 120000,
    memory: 1024
  }
}

// 已实现: src/gateway/sandbox.ts → CodeSandbox
```

### 2.4 文件系统沙盒

```typescript
// 路径隔离
allowed_paths = {
  '/tmp/agentzt/uploads': ['read', 'write'],
  '/data/public': ['read'],
  '/data/private': ['read'],  // 需要认证
  '/etc/secrets': []  // 禁止
}

// Seccomp-bpf 配置示例
seccomp_rules = {
  allow: ['read', 'write', 'open', 'close', 'exit'],
  deny: ['mount', 'sys_admin', 'sys_module', 'network']
}
```

### 2.5 资源配额

```yaml
per_agent_quotas:
  web_sandbox:
    concurrent: 2
    per_hour: 100
  code_execution:
    concurrent: 1
    per_hour: 50
    max_cpu_time: 30s
  file_operations:
    per_minute: 100
    max_file_size: 10MB
```

---

## 3. MCP 协议集成

### 3.1 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgentZT Gateway                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Policy Engine → RBAC Scope → Tool Registry              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                   │
│                            ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              MCP Client (官方 SDK)                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  ┌──────────┐        ┌──────────┐        ┌──────────┐
  │ Local    │        │ Remote   │        │ Custom   │
  │ MCP      │        │ MCP      │        │ MCP      │
  │ Servers  │        │ Servers  │        │ Servers  │
  └──────────┘        └──────────┘        └──────────┘
```

### 3.2 工具映射

```typescript
// 已实现: src/gateway/mcp-integration.ts

interface MCPToolMapping {
  mcpServerId: string;        // MCP 服务器 ID
  mcpToolName: string;         // MCP 工具名
  agentztToolName: string;     // AgentZT 映射名
  rbacScope: string;           // RBAC 权限范围
  parameterSchema: object;     // 参数 schema
}

// 自动映射示例
mcpToolMappings = [
  {
    mcpServerId: 'filesystem',
    mcpToolName: 'read_file',
    agentztToolName: 'mcp:filesystem:read_file',
    rbacScope: 'mcp.filesystem.read'
  },
  {
    mcpServerId: 'git',
    mcpToolName: 'git_status',
    agentztToolName: 'mcp:git:status',
    rbacScope: 'mcp.git.status'
  }
]
```

### 3.3 安全策略

```yaml
mcp_security:
  # 请求签名验证
  request_signing: true
  signature_algorithm: EdDSA

  # 资源访问控制
  resource_allowlist:
    - file:///tmp/agentzt/*
    - file:///data/public/*

  # 工具调用审计
  audit_all_calls: true
  audit_include_input: true
  audit_include_output: true

  # 速率限制
  rate_limits:
    per_agent: 100/minute
    per_tool: 50/minute
```

### 3.4 预置 MCP 服务器

```bash
# 文件系统
npx @modelcontextprotocol/server-filesystem /tmp/agentzt-files

# Git
npx @modelcontextprotocol/server-git

# Slack (需要配置)
npx @modelcontextprotocol/server-slack

# Brave Search
npx @modelcontextprotocol/server-brave-search

# AWS (生产环境)
npx @modelcontextprotocol/server-aws-kb-retrieval-server
```

---

## 4. LLM 智能路由

### 4.1 多模型支持

```yaml
providers:
  deepseek:
    base_url: https://api.deepseek.com/v1
    models:
      - deepseek-chat
      - deepseek-coder
    strengths:
      - 代码生成
      - 中文理解
      - 成本效益

  anthropic:
    base_url: https://api.anthropic.com/v1
    models:
      - claude-opus-4-8
      - claude-sonnet-4-6
      - claude-haiku-4-5
    strengths:
      - 复杂推理
      - 长上下文
      - 安全性
```

### 4.2 智能路由策略

```typescript
// 已实现: src/gateway/llm-gateway.ts

interface RouteRule {
  pattern: string;      // 模型名匹配
  provider: string;    // 目标 provider
  priority: number;     // 优先级
  conditions?: {
    max_tokens?: number;
    required_capabilities?: string[];
  };
}

// 路由规则
rules = [
  { pattern: 'claude-opus-*', provider: 'anthropic', priority: 1 },
  { pattern: 'claude-sonnet-*', provider: 'anthropic', priority: 1 },
  { pattern: 'claude-haiku-*', provider: 'anthropic', priority: 1 },
  { pattern: 'deepseek-*', provider: 'deepseek', priority: 1 },
  { pattern: '*', provider: 'deepseek', priority: 99 }  // 默认
]
```

### 4.3 成本优化

```yaml
cost_optimization:
  # 模型选择策略
  model_selection:
    simple_tasks:
      - deepseek-chat  # $0.001/1K tokens
    complex_tasks:
      - claude-sonnet-4-6
    max_reasoning:
      - claude-opus-4-8

  # Token 优化
  token_optimization:
    cache_enabled: true
    context_compression: true
    max_tokens_clamp: true

  # 预算控制
  budget_limits:
    per_agent_daily: $10
    per_role_monthly: $1000
```

---

## 5. 智能体框架

### 5.1 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgentZT Agent                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  🤖 Agent Brain (LLM + Prompt Engineering)               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  🔧 Tool Executor (策略检查 + 沙盒执行)                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                     │
│            ┌───────────────┼───────────────┐                    │
│            ▼               ▼               ▼                    │
│      ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│      │ Web      │    │ Code     │    │ MCP      │               │
│      │ Search   │    │ Executor │    │ Tools    │               │
│      └──────────┘    └──────────┘    └──────────┘               │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    AgentZT Gateway
```

### 5.2 工具注册

```typescript
// 已实现: src/gateway/agent-framework.ts

interface ToolDefinition {
  name: string;
  description: string;
  schema: JSONSchema;
  execute: (args, context) => Promise<Result>;
}

// 内置工具
builtin_tools = [
  {
    name: 'web_search',
    description: 'Web search via sandboxed browser',
    schema: {
      type: 'object',
      properties: { query: { type: 'string' } },
      required: ['query']
    }
  },
  {
    name: 'code_execute',
    description: 'Execute code in sandbox',
    schema: {
      type: 'object',
      properties: {
        language: { enum: ['javascript', 'python', 'bash'] },
        code: { type: 'string' }
      },
      required: ['language', 'code']
    }
  },
  {
    name: 'file_read',
    description: 'Read file contents',
    schema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    }
  },
  {
    name: 'mcp_tool',
    description: 'Call MCP server tool',
    schema: {
      type: 'object',
      properties: {
        server: { type: 'string' },
        tool: { type: 'string' },
        arguments: { type: 'object' }
      },
      required: ['server', 'tool']
    }
  }
]
```

### 5.3 安全执行流程

```
用户请求
    │
    ▼
┌─────────────────┐
│  身份验证        │ ← Ed25519 签名验证
│  AgentZT Token  │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  RBAC 策略检查   │ ← 角色权限验证
│  (tool scope)   │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  ABAC 检查      │ ← 时间/风险条件
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  沙盒执行       │ ← 资源隔离
│  (sandbox)      │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  输出审计       │ ← 敏感信息过滤
│  (guardrails)   │
└─────────────────┘
    │
    ▼
返回结果
```

### 5.4 任务执行

```typescript
// 任务状态机
task_states = {
  pending: '任务等待执行',
  running: '执行中 (iteration < max)',
  waiting_tool: '等待工具结果',
  waiting_llm: '等待 LLM 响应',
  completed: '完成 (无更多工具调用)',
  failed: '失败 (max iterations / error)'
}

// 迭代限制
execution_limits = {
  max_iterations: 10,        // 最大迭代次数
  max_tool_calls: 50,        // 最大工具调用
  max_total_time: 300000,    // 最大总时间 (5min)
  max_output_tokens: 4096    // 最大输出
}
```

---

## 6. 可视化控制台

### 6.1 功能模块

```yaml
控制台模块:
  dashboard:
    - 实时流量监控
    - Agent 活跃状态
    - 安全事件统计
    - 性能指标

  agent_management:
    - Agent 注册/注销
    - 角色分配
    - 密钥管理
    - 状态监控

  policy_editor:
    - RBAC 策略可视化
    - JSON Schema 编辑器
    - 策略版本历史
    - 语法验证

  audit_viewer:
    - 实时日志流
    - 高级过滤
    - 导出功能
    - 哈希验证

  mcp_manager:
    - MCP 服务器连接
    - 工具映射视图
    - 状态监控

  sandbox_monitor:
    - 执行记录
    - 资源使用
    - 隔离状态

  llm_router:
    - 模型配置
    - 路由规则
    - 成本统计
```

### 6.2 界面预览

已创建: `docs/console.html`

功能包括:
- 实时仪表盘 (统计卡片 + 流量图)
- Agent 管理界面
- 智能对话聊天
- 策略配置编辑器
- 审计日志查看器
- MCP 服务器管理
- 沙盒监控
- LLM 路由配置

### 6.3 技术选型

```yaml
前端:
  - 纯 HTML/CSS/JavaScript (MVP)
  - React/Vue (生产级)

UI 组件:
  - Tailwind CSS
  - shadcn/ui

图表:
  - Chart.js / D3.js
  - Recharts

实时通信:
  - WebSocket (SSE)
  - Server-Sent Events

状态管理:
  - Zustand (React)
  - Pinia (Vue)
```

---

## 7. 部署架构

### 7.1 Kubernetes 部署

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentzt-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: agentzt-gateway
  template:
    spec:
      containers:
        - name: gateway
          image: agentzt/gateway:latest
          ports:
            - containerPort: 8443
          env:
            - name: NODE_ENV
              value: production
            - name: KMS_TYPE
              value: aws
            - name: AWS_KMS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: agentzt-secrets
                  key: kms-key-id
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8443
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8443
```

### 7.2 服务网格配置

```yaml
# Istio VirtualService
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: agentzt-gateway
spec:
  hosts:
    - agentzt-gateway
  http:
    - match:
        - headers:
            x-agentzt-token:
              exists: true
      route:
        - destination:
            host: agentzt-gateway
            port:
              number: 8443
      retries:
        attempts: 3
        perTryTimeout: 2s
```

### 7.3 高可用架构

```
                    ┌─────────────────┐
                    │   Cloudflare   │
                    │   (WAF + CDN)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
         │ Kong GW │    │ Kong GW │    │ Kong GW │
         │ (AZ-1) │    │ (AZ-2)  │    │ (AZ-3)  │
         └────┬────┘    └────┬────┘    └────┬────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
         │Gateway  │    │Gateway  │    │Gateway  │
         │ Pod 1   │    │ Pod 2   │    │ Pod 3   │
         └────┬────┘    └────┬────┘    └────┬────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ Redis   │         │ S3/GCS  │         │  SIEM   │
    │ Cluster │         │ Audit   │         │  Log    │
    └─────────┘         └─────────┘         └─────────┘
```

---

## 8. 实施路线图

### Phase 1: 基础集成 (1-2 周)

- [ ] 沙盒集成完成 (`src/gateway/sandbox.ts`)
- [ ] LLM 路由完成 (`src/gateway/llm-gateway.ts`)
- [ ] 控制台 HTML 原型 (`docs/console.html`)

### Phase 2: MCP 集成 (2-3 周)

- [ ] MCP Client 实现 (`src/gateway/mcp-integration.ts`)
- [ ] 工具映射机制
- [ ] MCP 服务器连接管理

### Phase 3: 智能体框架 (2-3 周)

- [ ] 智能体执行引擎 (`src/gateway/agent-framework.ts`)
- [ ] 工具注册表
- [ ] 任务状态机

### Phase 4: 生产加固 (3-4 周)

- [ ] HSM/KMS 集成
- [ ] 不可变审计存储
- [ ] Kubernetes 部署配置
- [ ] 服务网格集成

### Phase 5: 可视化完善 (2-3 周)

- [ ] React/Vue 重构
- [ ] 实时数据更新
- [ ] 策略编辑器增强
- [ ] 审计日志可视化

---

## 文件清单

| 文件路径 | 说明 |
|---------|------|
| `src/gateway/llm-gateway.ts` | LLM 路由网关 (DeepSeek + Anthropic) |
| `src/gateway/sandbox.ts` | 沙盒集成层 (Web/Code/File) |
| `src/gateway/mcp-integration.ts` | MCP 协议集成 |
| `src/gateway/agent-framework.ts` | 智能体执行框架 |
| `docs/console.html` | 可视化控制台原型 |

---

## 下一步行动

1. **查看已创建的文件**
2. **运行 demo** 了解基础功能
3. **根据需求选择优先级**
4. **开始 Phase 1 实施**

有任何具体问题或需要深入某个模块，请告诉我！
