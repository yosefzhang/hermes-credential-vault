---
name: vault-usage
description: Credential Vault 使用指南 —— 加密存储和管理第三方系统凭证
version: 0.3.0
---

# Credential Vault 使用指南

加密存储你的 API 凭证（账号密码 / Bearer Token / SSO 登录），Hermes 代你调用系统 API 时凭证绝不进入对话记录或 LLM 上下文。

## 首次使用

### 1. 设置 PIN

```
/vault set-pin <PIN>
```

PIN 要求：**≥ 8 位，同时含小写字母、大写字母、数字、符号**。

### 2. 解锁

```
/vault unlock <PIN>
```

有效期 30 分钟（滑动过期，每次使用刷新）。

### 3. 绑定凭证

```bash
# Basic Auth（账号密码）
/vault bind <system> basic '<username>' '<password>' <base_url>

# Bearer Token
/vault bind <system> bearer '<token>' <base_url>

# SSO 认证（两步绑定）
/vault bind <provider> basic '<user>' '<pass>'                     # 1. 存 SSO 登录账密（多 system 共享）
/vault bind <system> sso <provider> <base_url>                     # 2. 声明 system 走 SSO
```

**凭证字段必须用单引号 `'...'` 包裹**（禁止双引号，禁止裸写）。单引号内特殊字符原样保留。

示例：
```bash
/vault bind jira basic 'yosef@example.com' 'MyP@ssw0rd!' https://ticket.example.com
/vault bind confluence bearer 'ATATT3xFfGF0abcdef...' https://conf.example.com
/vault bind quectel_sso basic 'yosef.zhang@quectel.com' 'MyPass!'
/vault bind devops sso quectel_sso https://devops.example.com
```

### 4. 开始使用

绑定并解锁后直接提问即可，Hermes 会自动调用已绑定的系统 API。

## SSO 系统（浏览器登录型）

SSO 登录由 `call_external_system` 工具**自动完成**，用户只需两步绑定即可：

```bash
# Step 1: 存 SSO 登录账密（只需一次，多 system 共享）
/vault bind quectel_sso basic '<user>' '<pass>'

# Step 2: 声明 system 走 SSO
/vault bind devops sso quectel_sso https://devops.example.com

# 之后直接提问即可，Hermes 自动完成 SSO 登录
```

**关键概念**：
- 账密存于 **provider**（如 `quectel_sso`），多个 system 共享一份
- System（如 `devops`）只存引用：`auth_type: sso, sso_provider: quectel_sso`
- 首次访问时自动触发登录，cookie 缓存到 vault
- Cookie 有效期由 SSO server 控制，`/vault sso-status` 查看剩余时间
- `/vault sso-logout <system>` 踢下所有共享该 provider 的系统

## 命令速查

| 命令 | 说明 |
|---|---|
| `/vault set-pin <PIN>` | 首次设置 PIN |
| `/vault unlock <PIN>` | 解锁（30min TTL） |
| `/vault bind <sys> basic '<user>' '<pass>' <url>` | 绑定 basic 认证 |
| `/vault bind <sys> bearer '<token>' <url>` | 绑定 bearer 认证 |
| `/vault bind <sys> sso <provider> <url>` | 绑定 SSO 认证 |
| `/vault bind <provider> basic '<user>' '<pass>'` | 存 SSO 登录账密 |
| `/vault unbind <sys>` | 解绑系统 |
| `/vault list` | 查看状态、系统绑定和可用 providers |
| `/vault sso-status [<sys>]` | 查看 SSO 会话状态 |
| `/vault sso-logout <sys>` | 删除本地 SSO 会话 |
| `/vault help` | 显示帮助 |

> 💡 SSO 登录由 call_external_system 工具自动完成，无需手动 /vault sso-login。

## 常见问题

**忘记 PIN？** 联系管理员删除 vault 目录，重新 `set-pin` + `bind`。**务必去各系统后台吊销旧凭证。**

**凭证安全吗？** 磁盘 AES-256-GCM 加密；`/vault` 命令不进对话历史/session/memory；agent 通过代理工具调用，凭证明文只在插件栈上短暂存活。唯一不可控暴露点是飞书聊天记录（建议发完后撤回）。

**群聊不能用 /vault？** 安全策略，强制只能私聊使用。

**SSO 自动登录失败？** 常见原因：账密错、SSO server 挂了、Playwright 未装（`pip install playwright && playwright install chromium`）。

**provider 账密未绑定？** 如果自动登录失败，需先 `/vault bind <provider> basic '<user>' '<pass>'`。