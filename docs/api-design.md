# AgentZT 管理 API 设计规范

本文档定义了 AgentZT Gateway 管理API的设计规范，包括设计原则、资源命名、HTTP方法使用、响应格式和错误处理等。

## 1. API 设计原则

### 1.1 RESTful 设计

AgentZT 管理 API 采用 RESTful 架构风格，遵循以下核心原则：

- **资源导向**: API 以资源为中心，每个资源有唯一的 URI
- **统一接口**: 使用标准 HTTP 方法（GET、POST、PUT、DELETE）操作资源
- **无状态**: 每个请求包含所有必要信息，不依赖服务器端会话状态
- **可缓存**: 响应明确标识是否可缓存
- **分层系统**: 支持中间层（代理、负载均衡器）而不影响客户端

### 1.2 API 版本控制

API 使用 URL 路径版本控制：

```
/api/v1/apps
/api/v2/apps  (未来版本)
```

当前版本为 v1，默认路径 `/api` 等同于 `/api/v1`。

### 1.3 安全原则

- **认证**: 所有管理 API 需要 Bearer Token 认证
- **授权**: 基于 RBAC（角色访问控制）和资源所有权
- **传输安全**: 强制 HTTPS
- **输入验证**: 严格验证所有输入参数
- **敏感数据**: API Key 等敏感数据仅在创建/重新生成时返回

## 2. 资源命名规范

### 2.1 URI 命名规则

| 规则 | 示例 | 说明 |
|------|------|------|
| 使用复数名词 | `/api/apps` | 资源集合使用复数形式 |
| 使用小写字母 | `/api/apps` | 避免大小写混淆 |
| 使用连字符分隔 | `/api/risk-categories` | 多词名称使用 `-` 连接 |
| 避免文件扩展名 | `/api/apps/{id}` | 不使用 `.json` 等扩展名 |
| 层级结构清晰 | `/api/apps/{appId}/config` | 表达资源关系 |

### 2.2 资源层级

```
/api
├── /auth                    # 认证相关
│   ├── /register           # 用户注册
│   ├── /login              # 用户登录
│   ├── /refresh            # 刷新令牌
│   ├── /logout             # 登出
│   └── /me                 # 当前用户信息
│
├── /apps                    # 应用管理
│   ├── /                   # 应用列表/创建
│   ├── /{appId}            # 单个应用操作
│   │   ├── /config         # 应用配置
│   │   │   ├── /risk-types           # 风险类型配置
│   │   │   ├── /risk-categories      # 风险类别配置
│   │   │   ├── /blacklist-whitelist  # 黑白名单
│   │   │   ├── /response-templates   # 响应模板
│   │   │   ├── /sensitivity          # 敏感度配置
│   │   │   ├── /ban-policy           # 封禁策略
│   │   │   └── /knowledge-base       # 知识库
│   │   └── /regenerate-key # 重新生成 API Key
│   └── /by-key/{apiKey}    # 按 API Key 查询（内部）
│
├── /quota                   # 配额管理
│   ├── /usage              # 当前配额使用
│   ├── /history            # 配额使用历史
│   ├── /reset              # 重置配额（管理员）
│   ├── /limit              # 设置配额限制（管理员）
│   └── /alerts             # 配额告警历史
│
├── /stats                   # 统计分析
│   ├── /overview           # 统计概览
│   ├── /risk-distribution  # 风险分布
│   ├── /trend              # 趋势数据
│   └── /export             # 导出统计数据
│
└── /alerts                  # 告警管理
    ├── /                   # 告警列表
    ├── /{alertId}          # 单个告警详情
    ├── /rules              # 告警规则配置
    └── /settings           # 告警设置
```

### 2.3 资源标识符

- **appId**: 格式为 `app-{timestamp}-{random}`，例如 `app-1699887600000-a1b2c3d4`
- **userId**: 格式为 `user-{timestamp}-{random}`
- **alertId**: 格式为 `alert-{timestamp}-{random}`
- **requestId**: UUID 格式

## 3. HTTP 方法使用规范

### 3.1 方法语义

| 方法 | 语义 | 幂等性 | 安全性 | 示例 |
|------|------|--------|--------|------|
| GET | 获取资源 | 是 | 是 | 获取应用列表 |
| POST | 创建资源/执行操作 | 否 | 否 | 创建新应用 |
| PUT | 更新资源（完整替换） | 是 | 否 | 更新应用配置 |
| PATCH | 部分更新资源 | 否 | 否 | 部分更新配置 |
| DELETE | 删除资源 | 是 | 否 | 删除应用 |

### 3.2 方法使用示例

```http
# 获取应用列表
GET /api/apps

# 创建新应用
POST /api/apps
Content-Type: application/json
{
  "name": "My App",
  "tier": "business"
}

# 获取单个应用
GET /api/apps/app-1699887600000-a1b2c3d4

# 更新应用
PUT /api/apps/app-1699887600000-a1b2c3d4
Content-Type: application/json
{
  "name": "Updated App Name"
}

# 删除应用
DELETE /api/apps/app-1699887600000-a1b2c3d4

# 重新生成 API Key（非幂等操作）
POST /api/apps/app-1699887600000-a1b2c3d4/regenerate-key
```

### 3.3 批量操作

批量操作使用 POST 方法：

```http
# 批量添加黑名单关键词
POST /api/apps/{appId}/config/blacklist
Content-Type: application/json
{
  "keywords": ["keyword1", "keyword2", "keyword3"]
}
```

## 4. 响应格式规范

### 4.1 成功响应

#### 单个资源

```json
{
  "appId": "app-1699887600000-a1b2c3d4",
  "name": "My Application",
  "apiKey": "agt_sk_xxx...",
  "modelApiKey": "agt_mk_xxx...",
  "config": {
    "riskTypes": { "security": true, "compliance": true, "dataSecurity": true },
    "riskCategories": { "S1": true, "S2": true, ... },
    "blacklistWhitelist": { "blacklist": [], "whitelist": [] },
    "responseTemplates": { "reject": "...", "replace": "..." },
    "sensitivity": { "level": "medium", "threshold": 0.7 },
    "banPolicy": { "bannedUsers": [], "autoBanThreshold": 3 },
    "knowledgeBase": { "entries": [] }
  },
  "quota": {
    "checksLimit": 10000,
    "checksUsed": 150,
    "tokensLimit": 1000000,
    "tokensUsed": 25000
  },
  "createdAt": "2024-01-15T10:30:00Z",
  "ownerId": "user-xxx"
}
```

#### 资源集合

```json
{
  "apps": [
    { "appId": "...", "name": "..." },
    { "appId": "...", "name": "..." }
  ],
  "total": 2
}
```

#### 操作结果

```json
{
  "success": true,
  "message": "Application deleted successfully",
  "appId": "app-xxx"
}
```

### 4.2 分页响应

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "pageSize": 20,
    "total": 100,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  }
}
```

### 4.3 时间戳格式

- 所有时间戳使用 ISO 8601 格式：`2024-01-15T10:30:00Z`
- 时区使用 UTC（以 `Z` 结尾）

### 4.4 数值精度

- 百分比使用 0-1 范围的小数：`0.85` 表示 85%
- 保留 3 位小数精度

## 5. 错误处理规范

### 5.1 错误响应格式

```json
{
  "error": {
    "code": "authentication_error",
    "message": "User not authenticated",
    "details": {
      "field": "Authorization",
      "reason": "Missing or invalid Bearer token"
    },
    "requestId": "req-xxx-xxx-xxx",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### 5.2 错误代码分类

| 类别 | HTTP 状态码 | 错误代码 | 说明 |
|------|-------------|----------|------|
| 认证错误 | 401 | `authentication_error` | 未认证或令牌无效 |
| 权限错误 | 403 | `permission_error` | 无权限访问资源 |
| 资源不存在 | 404 | `not_found` | 资源不存在 |
| 请求错误 | 400 | `invalid_request` | 请求参数无效 |
| 验证错误 | 400 | `validation_error` | 数据验证失败 |
| 冲突错误 | 409 | `conflict_error` | 资源冲突（如重复创建） |
| 速率限制 | 429 | `rate_limit_exceeded` | 超过请求速率限制 |
| 内部错误 | 500 | `internal_error` | 服务器内部错误 |
| 服务不可用 | 503 | `service_unavailable` | 服务暂时不可用 |

### 5.3 错误处理最佳实践

1. **明确的错误信息**: 提供清晰、可操作的错误描述
2. **一致的错误格式**: 所有错误使用统一格式
3. **请求追踪**: 每个错误包含 `requestId` 用于追踪
4. **文档化错误**: 在 API 文档中列出所有可能的错误

### 5.4 常见错误示例

```json
// 认证错误
{
  "error": {
    "code": "authentication_error",
    "message": "User not authenticated"
  }
}

// 权限错误
{
  "error": {
    "code": "permission_error",
    "message": "You do not have access to this application"
  }
}

// 验证错误
{
  "error": {
    "code": "invalid_request",
    "message": "App name must be between 1 and 100 characters",
    "details": {
      "field": "name",
      "value": "",
      "constraint": "minLength: 1, maxLength: 100"
    }
  }
}

// 资源不存在
{
  "error": {
    "code": "not_found",
    "message": "Application \"app-xxx\" not found"
  }
}
```

## 6. 认证与授权

### 6.1 认证方式

使用 Bearer Token 认证：

```http
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

### 6.2 令牌类型

| 令牌类型 | 用途 | 有效期 |
|----------|------|--------|
| Session Token | 用户会话认证 | 24 小时 |
| Refresh Token | 刷新会话令牌 | 7 天 |
| API Key | 应用身份认证 | 永久（可重新生成） |

### 6.3 角色权限

| 角色 | 权限 |
|------|------|
| `owner` | 完全访问权限，可管理所有资源 |
| `admin` | 管理权限，可修改配置、管理应用 |
| `viewer` | 只读权限，仅可查看配置和数据 |

### 6.4 资源所有权

- 用户只能访问自己创建的应用
- 管理员可以访问所有应用
- 应用配置修改需要 `admin` 或 `owner` 角色

## 7. 请求头规范

### 7.1 必需请求头

```http
Content-Type: application/json
Authorization: Bearer {token}
```

### 7.2 可选请求头

```http
# 应用选择器（用于多应用场景）
X-AgentZT-App-ID: {appId}
X-AgentZT-API-Key: {apiKey}

# 用户标识（开发测试用）
X-User-ID: {userId}

# 请求追踪
X-Request-ID: {requestId}
```

### 7.3 响应头

```http
Content-Type: application/json
X-Request-ID: {requestId}
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699887600
```

## 8. 查询参数规范

### 8.1 过滤参数

```http
GET /api/apps?tier=business
GET /api/stats/overview?timeRange=week&appId=app-xxx
```

### 8.2 分页参数

```http
GET /api/apps?page=1&pageSize=20
GET /api/quota/history?limit=100
```

### 8.3 排序参数

```http
GET /api/apps?sort=createdAt&order=desc
```

### 8.4 时间范围参数

```http
GET /api/stats/trend?timeRange=month&granularity=day
```

支持的值：
- `timeRange`: `day`, `week`, `month`, `year`
- `granularity`: `hour`, `day`

## 9. API 端点摘要

### 9.1 认证 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/auth/register` | POST | 用户注册 |
| `/api/auth/login` | POST | 用户登录 |
| `/api/auth/refresh` | POST | 刷新令牌 |
| `/api/auth/logout` | POST | 用户登出 |
| `/api/auth/me` | GET | 获取当前用户信息 |

### 9.2 应用管理 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/apps` | GET | 获取应用列表 |
| `/api/apps` | POST | 创建新应用 |
| `/api/apps/{appId}` | GET | 获取应用详情 |
| `/api/apps/{appId}` | PUT | 更新应用 |
| `/api/apps/{appId}` | DELETE | 删除应用 |
| `/api/apps/{appId}/regenerate-key` | POST | 重新生成 API Key |

### 9.3 配置管理 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/apps/{appId}/config/risk-types` | GET/PUT | 风险类型配置 |
| `/api/apps/{appId}/config/risk-categories` | GET/PUT | 风险类别配置 |
| `/api/apps/{appId}/config/blacklist-whitelist` | GET | 黑白名单配置 |
| `/api/apps/{appId}/config/blacklist` | POST/DELETE | 黑名单操作 |
| `/api/apps/{appId}/config/whitelist` | POST/DELETE | 白名单操作 |
| `/api/apps/{appId}/config/response-templates` | GET/PUT | 响应模板配置 |
| `/api/apps/{appId}/config/sensitivity` | GET/PUT | 敏感度配置 |
| `/api/apps/{appId}/config/ban-policy` | GET/PUT | 封禁策略配置 |
| `/api/apps/{appId}/config/ban-policy/ban` | POST/DELETE | 封禁用户操作 |
| `/api/apps/{appId}/config/knowledge-base` | GET/POST | 知识库操作 |

### 9.4 统计分析 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/stats/overview` | GET | 统计概览 |
| `/api/stats/risk-distribution` | GET | 风险分布 |
| `/api/stats/trend` | GET | 趋势数据 |
| `/api/stats/export` | GET | 导出统计数据 |

### 9.5 配额管理 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/quota/usage` | GET | 当前配额使用 |
| `/api/quota/history` | GET | 配额使用历史 |
| `/api/quota/reset` | POST | 重置配额（管理员） |
| `/api/quota/limit` | PUT | 设置配额限制（管理员） |
| `/api/quota/alerts` | GET | 配额告警历史 |

### 9.6 告警管理 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/alerts` | GET | 告警列表 |
| `/api/alerts/{alertId}` | GET | 告警详情 |
| `/api/alerts/rules` | GET/PUT | 告警规则配置 |
| `/api/alerts/settings` | GET/PUT | 告警设置 |

## 10. SDK 使用指南

### 10.1 Python SDK

```python
from agentzt import Client

# 初始化客户端
client = Client(base_url="https://gateway.example.com", api_key="agt_sk_xxx")

# 获取应用列表
apps = client.apps.list()

# 创建新应用
app = client.apps.create(name="My App", tier="business")

# 获取统计概览
stats = client.stats.overview(time_range="week")
```

### 10.2 JavaScript SDK

```typescript
import { Client } from 'agentzt';

// 初始化客户端
const client = new Client({
  baseUrl: 'https://gateway.example.com',
  apiKey: 'agt_sk_xxx'
});

// 获取应用列表
const apps = await client.apps.list();

// 创建新应用
const app = await client.apps.create({ name: 'My App', tier: 'business' });

// 获取统计概览
const stats = await client.stats.overview({ timeRange: 'week' });
```

## 11. 最佳实践

### 11.1 客户端实现建议

1. **重试机制**: 对 5xx 错误实现指数退避重试
2. **超时设置**: 设置合理的请求超时（建议 30 秒）
3. **错误处理**: 捕获并处理所有可能的错误
4. **令牌刷新**: 自动刷新即将过期的令牌
5. **请求追踪**: 记录请求 ID 用于问题排查

### 11.2 性能优化

1. **批量操作**: 使用批量 API 减少请求次数
2. **缓存策略**: 缓存不常变化的数据
3. **分页查询**: 大数据集使用分页获取
4. **压缩传输**: 启用 gzip 响应压缩

### 11.3 安全建议

1. **令牌存储**: 安全存储 API Key 和令牌
2. **HTTPS**: 强制使用 HTTPS 连接
3. **最小权限**: 使用最小必要权限的令牌
4. **定期轮换**: 定期重新生成 API Key

---

**文档版本**: 1.0.0  
**最后更新**: 2024-01-15  
**维护者**: AgentZT Team