# hermes-credential-vault

Hermes Agent 多工程师凭证隔离插件 —— 安全加密存储 JIRA / Confluence / PMS 的 API Token。

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

### 2. 配置系统

在 `~/.hermes/config.yaml` 中添加：

```yaml
plugins:
  entries:
    hermes-credential-vault:
      # 可选：自定义 vault 存储目录（支持 {profile} 占位符）
      storage_dir: ~/.config/hermes-credential-vault/{profile}-vault

      # 声明本插件管理的系统（只需系统名，base_url 在 bind 时指定）
      systems:
        - jira
        - confluence
        - pms
        - devops
```

**说明**：
- `systems` 只需声明系统名列表
- `base_url` 在 `/vault bind` 时由用户指定，加密存储
- 每个用户可以使用不同的 base_url（如测试/生产环境）

### 3. 重启 Gateway

```bash
hermes gateway restart --profile <profile_name>
```

### 4. 测试连通

从飞书私聊发送 `/vault help`，如果收到命令帮助，说明插件正常工作。

## 卸载

```bash
hermes plugins remove hermes-credential-vault --profile <profile_name>
hermes gateway restart --profile <profile_name>
```

## CLI 命令参考

### 基础命令

#### `/vault set-pin <PIN>`

首次设置 PIN。

- **参数**: `<PIN>` — 密码
- **PIN 要求**: ≥ 8 位，同时含小写字母、大写字母、数字、符号
- **示例**:
  ```
  /vault set-pin MyP@ssw0rd!
  ```

#### `/vault unlock <PIN>`

解锁 vault，有效期 30 分钟（滑动过期，每次使用刷新）。

- **参数**: `<PIN>` — 密码
- **示例**:
  ```
  /vault unlock MyP@ssw0rd!
  ```

#### `/vault list`

查看 vault 状态、系统绑定情况和可用 SSO providers。

- **参数**: 无
- **示例**:
  ```
  /vault list
  ```

#### `/vault help`

显示帮助信息。

- **参数**: 无
- **示例**:
  ```
  /vault help
  ```

### 凭证绑定

#### `/vault bind <system> basic '<username>' '<password>' <base_url>`

绑定 Basic 认证凭证。

- **参数**:
  - `<system>` — 系统名（需在 config.yaml 中声明）
  - `'<username>'` — 用户名（必须用单引号包裹）
  - `'<password>'` — 密码（必须用单引号包裹）
  - `<base_url>` — 系统 URL（必填）
- **示例**:
  ```
  /vault bind jira basic 'yosef@example.com' 'MyP@ssw0rd!' https://ticket.example.com
  /vault bind pms basic 'admin' 'secret123' https://pms.custom.com
  ```

#### `/vault bind <system> bearer '<token>' <base_url>`

绑定 Bearer Token 凭证。

- **参数**:
  - `<system>` — 系统名
  - `'<token>'` — API Token（必须用单引号包裹）
  - `<base_url>` — 系统 URL（必填）
- **示例**:
  ```
  /vault bind jira bearer 'ATATT3xFfGF0abcdef...' https://ticket.example.com
  ```

#### `/vault bind <system> sso <provider> <base_url>`

绑定 SSO 认证（声明系统使用哪个 SSO provider）。

- **参数**:
  - `<system>` — 系统名
  - `<provider>` — SSO provider 名（通过 `/vault list` 查看可用 providers）
  - `<base_url>` — 系统 URL（必填）
- **示例**:
  ```
  /vault bind devops sso quectel_sso https://devops.example.com
  ```

#### `/vault bind <provider> basic '<username>' '<password>'`

为 SSO provider 绑定登录账密（多个 system 共享）。

- **参数**:
  - `<provider>` — SSO provider 名
  - `'<username>'` — 用户名
  - `'<password>'` — 密码
- **示例**:
  ```
  /vault bind quectel_sso basic 'yosef@example.com' 'MyP@ssw0rd!'
  ```

**注意**: 如果 provider 已有绑定，需要加 `--force` 强制覆盖：
```
/vault bind quectel_sso basic 'newuser@example.com' 'NewPass!' --force
```

#### `/vault unbind <system>`

解绑系统凭证。

- **参数**: `<system>` — 系统名或 provider 名
- **示例**:
  ```
  /vault unbind jira
  /vault unbind quectel_sso
  ```

### SSO 会话管理

#### `/vault sso-login <system>`

触发 SSO 浏览器登录，获取 cookie 会话。

- **参数**: `<system>` — SSO 系统名
- **前提**: 需先绑定 provider 账密
- **示例**:
  ```
  /vault sso-login devops
  ```

#### `/vault sso-status [<system>]`

查看 SSO 会话状态。

- **参数**: `[<system>]` — 可选，指定系统名；不指定则显示所有 SSO 系统状态
- **示例**:
  ```
  /vault sso-status
  /vault sso-status devops
  ```

#### `/vault sso-logout <system>`

删除本地 SSO 会话。

- **参数**: `<system>` — SSO 系统名
- **注意**: 由于 session 按 provider 存储，logout 会影响所有共享该 provider 的系统
 - **示例**:
  ```
  /vault sso-logout devops
  ```

## 使用流程

### Basic/Bearer 认证系统

```
1. /vault set-pin <PIN>           # 首次设置 PIN
2. /vault unlock <PIN>            # 解锁 vault
3. /vault bind jira basic 'user' 'pass' https://ticket.example.com  # 绑定凭证
4. 直接提问即可                    # Hermes 自动调用 API
```

### SSO 认证系统

```
1. /vault set-pin <PIN>
2. /vault unlock <PIN>
3. /vault bind quectel_sso basic 'user' 'pass'                    # 绑定 provider 账密
4. /vault bind devops sso quectel_sso https://devops.example.com  # 声明系统走 SSO
5. /vault sso-login devops                      # 触发 SSO 登录
6. 直接提问即可
```

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
