---
name: vault-usage
description: Credential Vault 使用指南 —— 加密存储和管理第三方系统凭证
version: 0.3.0
---

# Credential Vault 使用指南

加密存储你的 API 凭证（账号密码 / Bearer Token），Hermes 代你调用系统 API 时凭证绝不进入对话记录或 LLM 上下文。

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

```
/vault bind <system> basic '<username>' '<password>'
/vault bind <system> bearer '<token>'
```

**凭证字段必须用单引号 `'...'` 包裹**（禁止双引号，禁止裸写）。单引号内特殊字符原样保留。

示例：
```
/vault bind jira basic 'yosef@example.com' 'MyP@ssw0rd!'
/vault bind confluence bearer 'ATATT3xFfGF0abcdef...'
```

### 4. 开始使用

绑定并解锁后直接提问即可，Hermes 会自动调用已绑定的系统 API。

## 命令速查

| 命令 | 说明 |
|---|---|
| `/vault set-pin <PIN>` | 首次设置 PIN |
| `/vault unlock <PIN>` | 解锁（30min TTL） |
| `/vault lock` | 立即锁定 |
| `/vault bind <sys> basic '<user>' '<pass>'` | 绑定账号密码 |
| `/vault bind <sys> bearer '<token>'` | 绑定 Token |
| `/vault list` | 列出系统绑定状态 |
| `/vault revoke <sys>` | 删除本地凭证 |
| `/vault status` | 查看状态和 TTL |
| `/vault audit` | 查看审计日志 |
| `/vault help` | 显示帮助 |

## 常见问题

**忘记 PIN？** 联系管理员删除 vault 目录，重新 `set-pin` + `bind`。**务必去各系统后台吊销旧凭证。**

**凭证安全吗？** 磁盘 AES-256-GCM 加密；`/vault` 命令不进对话历史/session/memory；agent 通过代理工具调用，凭证明文只在插件栈上短暂存活。唯一不可控暴露点是飞书聊天记录（建议发完后撤回）。

**群聊不能用 /vault？** 安全策略，强制只能私聊使用。

**绑定报"未在 config.yaml 中声明"？** 需管理员先在 config.yaml 添加该系统并重启 gateway。
