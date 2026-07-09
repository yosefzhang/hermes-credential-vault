# hermes-credential-vault

Hermes Agent 多工程师凭证隔离插件，用于加密存储第三方系统的登录账号、密码、token等敏感信息。可以有效隔离用户间密钥泄露。

## 特性

- **磁盘加密**：AES-256-GCM + Argon2id KDF，凭证从不以明文落盘
- **消息隔离**：`/vault` 命令在 gateway 层被拦截，不进 session_store / memory / LLM
- **代理调用**：Agent 通过 `call_external_system` 工具代调 API，token 从不进入 LLM 上下文
- **30min TTL**：解锁后 30 分钟滑动过期，超时自动锁定并内存覆写清零
- **加密审计**：所有 vault 操作记录在加密审计日志中

## 安装

```bash
pip install -r requirements.txt
```

## 部署

### 1. 启用插件

```bash
hermes plugins enable hermes-credential-vault --profile <profile_name>
```

### 2. 重启 Gateway

```bash
hermes gateway restart --profile <profile_name>
```

### 3. 测试连通

从飞书私聊发送 `/vault help`，如果收到命令帮助，说明插件正常工作。

## 卸载

```bash
hermes plugins remove hermes-credential-vault --profile <profile_name>
hermes gateway restart --profile <profile_name>
```

## 使用指南

见 `skills/vault-usage/SKILL.md`，或在飞书私聊发送 `/vault help`。

## 测试

```bash
cd tests && python3 -m pytest -v
```

## 排错

**查看日志**：
```bash
grep hermes-credential-vault ~/.hermes/logs/agent.log
```

**插件未加载**：
- 确认 `plugins.enabled` 中包含 `hermes-credential-vault`
- 确认已重启 gateway

**`/vault help` 无回复**：
- 确认是私聊而非群聊（/vault 禁止群聊）
- 检查日志中的错误

**忘记 PIN**：
1. 联系管理员删除 vault 目录
2. 重新 `/vault set-pin` + `/vault bind`
3. **务必**去各系统后台吊销旧 token

## 安全边界

| 攻击者 | 防护 |
|---|---|
| 其他工程师 | ❌ 飞书应用白名单 + profile 隔离 |
| 同机非 root 账号 | ❌ vault 文件权限 0600 + 加密 |
| root（被动读磁盘） | ❌ 只有密文，无明文 |
| root（已解锁窗口内抓内存） | ⚠️ 能读到当前用户的 derived_key |
| root（主动改代码） | ⚠️ 依赖组织信任 + 代码变更留痕 |
| AI 模型幻觉 | ❌ Agent 从未见过 token |
