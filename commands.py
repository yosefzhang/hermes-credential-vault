"""/vault 子命令处理 —— set-pin / bind / unlock / lock / list / revoke / status / audit / help。

所有命令处理函数均为 async，返回给用户看的脱敏回复文本。
"""

import logging
import re
import shlex
from typing import Optional

try:
    from .audit import AuditLog, EVENT_TYPES
    from .constants import (
        CMD_PREFIX,
        AUTH_TYPE_BASIC,
        AUTH_TYPE_BEARER,
        SUPPORTED_AUTH_TYPES,
    )
    from .vault_core import (
        VaultCore,
        SessionKeyCache,
        AlreadyInitializedError,
        BadPinError,
        NotBoundError,
        VaultLockedError,
        WeakPinError,
        _validate_pin_strength,
    )
except ImportError:
    from audit import AuditLog, EVENT_TYPES  # type: ignore[no-redef]
    from constants import (  # type: ignore[no-redef]
        CMD_PREFIX,
        AUTH_TYPE_BASIC,
        AUTH_TYPE_BEARER,
        SUPPORTED_AUTH_TYPES,
    )
    from vault_core import (  # type: ignore[no-redef]
        VaultCore,
        SessionKeyCache,
        AlreadyInitializedError,
        BadPinError,
        NotBoundError,
        VaultLockedError,
        WeakPinError,
        _validate_pin_strength,
    )

logger = logging.getLogger(__name__)

# 模块级单例引用（由 __init__.py 在 register() 时注入）
_vault: Optional[VaultCore] = None
_session_cache: Optional[SessionKeyCache] = None
_audit: Optional[AuditLog] = None


def set_context(vault: VaultCore, cache: SessionKeyCache, audit: AuditLog) -> None:
    """注入模块级单例（避免循环 import）。"""
    global _vault, _session_cache, _audit
    _vault = vault
    _session_cache = cache
    _audit = audit


# ============================================================================
# 派发入口
# ============================================================================

async def dispatch_vault_command(text: str, user_id: str, event) -> str:
    """解析 /vault <subcommand> [args...] 并派发到对应处理函数。

    在派发前先执行统一的安全前置检查：
      - set-pin / status / help   → 豁免（未初始化时也允许）
      - unlock                     → 需要已初始化，无需 unlock
      - 其他                       → 需要已初始化 + 已 unlock

    另外 bind 命令的凭证字段（username / password / token）强制单引号包裹。

    返回给用户看的回复文本（已脱敏，不含 token）。
    """
    try:
        parts = shlex.split(text)
    except ValueError as e:
        return f"❌ 命令解析失败: {e}\n💡 提示：含特殊字符的密码请用单引号包裹，例如 'my$pass!'"

    if len(parts) < 2:
        return await cmd_help(user_id, [])

    subcommand = parts[1].lower()
    args = parts[2:]

    # 子命令路由表
    handlers = {
        "set-pin": cmd_set_pin,
        "bind": cmd_bind,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "status": cmd_status,
        "audit": cmd_audit,
        "help": cmd_help,
        "audit-log": cmd_audit,
    }

    handler = handlers.get(subcommand)
    if handler is None:
        return f"❌ 未知命令: /vault {subcommand}\n输入 /vault help 查看可用命令"

    # === 统一安全前置检查 ===
    exempt_subcmds = {"set-pin", "status", "help"}
    init_only_subcmds = {"unlock"}

    if subcommand not in exempt_subcmds:
        if not _vault.is_initialized():
            return f"❌ vault 未初始化，请先 {CMD_PREFIX} set-pin <PIN>"

        if subcommand not in init_only_subcmds:
            if _session_cache.get(user_id) is None:
                return f"❌ vault 未解锁或已超时，请先 {CMD_PREFIX} unlock <PIN>"

    # === bind 命令：凭证字段强制单引号包裹 ===
    if subcommand == "bind":
        err = _validate_bind_quotes(text)
        if err is not None:
            return err

    try:
        return await handler(user_id, args)
    except Exception as e:
        logger.error("命令执行异常: user_id=%s command=%s error=%s", user_id, subcommand, e)
        return f"❌ 命令执行失败: {type(e).__name__}"


# ============================================================================
# bind 命令引号校验
# ============================================================================

def _validate_bind_quotes(raw_text: str) -> Optional[str]:
    """强制 bind 命令的凭证字段（username/password/token）用单引号包裹。

    规则：
      /vault bind <system> basic '<username>' '<password>'
      /vault bind <system> bearer '<token>'

    - 允许单引号 '...'
    - 禁止双引号 "..."（避免反斜杠转义歧义）
    - 禁止裸写（避免空格/特殊字符解析事故）

    返回：
      None     → 校验通过
      错误字符串 → 返回给用户的错误提示
    """
    stripped = raw_text.strip()

    # 提取 "system" + "auth_type" + rest（凭证段原文）
    m = re.match(
        r"^/vault\s+bind\s+(\S+)\s+(\S+)\s*(.*)$",
        stripped,
        flags=re.IGNORECASE,
    )
    if not m:
        # 参数不足或格式怪异 → 交给 cmd_bind 出用法提示
        return None

    auth_type = m.group(2).lower()
    rest = m.group(3).strip()

    quote_hint = (
        "\n📝 凭证字段必须用单引号 '...' 包裹（禁止双引号 \"...\"）\n"
        f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>'\n"
        f"  {CMD_PREFIX} bind <system> bearer '<token>'\n"
        "示例:\n"
        f"  {CMD_PREFIX} bind jira basic 'yosef@example.com' 'MyP@ssw0rd!'\n"
        f"  {CMD_PREFIX} bind jira bearer 'ATATT3xFfGF0...'"
    )

    if auth_type == "basic":
        # 期望 2 个单引号段：'user' 'pass'
        pattern = r"^'([^']*)'\s+'([^']*)'\s*$"
        if not re.match(pattern, rest):
            return "❌ basic 认证的 username 和 password 必须用单引号 '...' 包裹。" + quote_hint

    elif auth_type == "bearer":
        # 期望 1 个单引号段：'token'
        pattern = r"^'([^']*)'\s*$"
        if not re.match(pattern, rest):
            return "❌ bearer 认证的 token 必须用单引号 '...' 包裹。" + quote_hint

    else:
        # 其他 auth_type 交给 cmd_bind 报错（会说"必须显式 basic / bearer"）
        return None

    # 校验通过（如果凭证里需要含单引号 '，POSIX shell 也做不到直接嵌套，
    # 用户需要改密码 / 换成不含单引号的 token，这是引号包裹方案的固有约束）
    return None


# ============================================================================
# 子命令实现
# ============================================================================

async def cmd_set_pin(user_id: str, args: list[str]) -> str:
    """首次设置 PIN：/vault set-pin <PIN>"""
    if _vault.is_initialized():
        return "❌ vault 已初始化。如需重置，请联系管理员删除 vault 目录后重新设置"

    if len(args) < 1:
        return f"用法: {CMD_PREFIX} set-pin <PIN>\nPIN 要求：≥ 8 位，含小写字母、大写字母、数字、符号"

    pin = args[0]
    try:
        _vault.initialize_pin(pin)
    except WeakPinError as e:
        return f"❌ PIN 强度不足: {e}"
    except AlreadyInitializedError:
        return "❌ vault 已初始化"

    logger.info("user_id=%s vault 初始化完成", user_id)
    return f"✅ PIN 已设置。下一步: {CMD_PREFIX} unlock <PIN> 解锁后 {CMD_PREFIX} bind <system> basic|bearer ... 绑定凭证"


def _get_configured_systems() -> list[str]:
    """从 __init__.py 读取运行时声明的系统列表（config.yaml 决定）。"""
    try:
        from . import get_systems_config
    except ImportError:  # pragma: no cover
        from __init__ import get_systems_config  # type: ignore[no-redef]
    return sorted(get_systems_config().keys())


async def cmd_bind(user_id: str, args: list[str]) -> str:
    """绑定系统凭证：
        /vault bind <system> basic <username> <password>
        /vault bind <system> bearer <token>

    system 必须在 config.yaml 的 systems 段中声明，否则拒绝。
    """
    key = _session_cache.get(user_id)
    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    configured = _get_configured_systems()
    usage = (
        f"用法:\n"
        f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>'\n"
        f"  {CMD_PREFIX} bind <system> bearer '<token>'\n"
        f"📝 凭证字段必须用单引号 '...' 包裹（禁止双引号）\n"
        f"可用系统（config.yaml 声明）: {', '.join(configured) if configured else '(空)'}"
    )

    if len(args) < 2:
        return usage

    system = args[0].lower()
    auth_type = args[1].lower()

    # 1. 校验 system 在 config.yaml 中声明
    if system not in configured:
        return (
            f"❌ system '{system}' 未在 config.yaml 中声明，本插件不管理该系统。\n"
            f"请先在 plugins.entries.hermes-credential-vault.systems 下添加，然后重启 gateway。\n"
            f"当前已声明: {', '.join(configured) if configured else '(空)'}"
        )

    # 2. 校验 auth_type 显式且合法
    if auth_type not in SUPPORTED_AUTH_TYPES:
        return (
            f"❌ 认证类型必须显式指定为 basic 或 bearer，收到: '{auth_type}'\n\n{usage}"
        )

    # 3. 按 auth_type 校验参数并组装凭证结构
    if auth_type == AUTH_TYPE_BASIC:
        if len(args) < 4:
            return f"❌ basic 认证需要 <username> <password>\n\n{usage}"
        username, password = args[2], args[3]
        if not username or not password:
            return "❌ username 和 password 不能为空"
        credential = {
            "auth_type": AUTH_TYPE_BASIC,
            "username": username,
            "password": password,
        }
    else:  # bearer
        if len(args) < 3:
            return f"❌ bearer 认证需要 <token>\n\n{usage}"
        token = args[2]
        if not token:
            return "❌ token 不能为空"
        credential = {
            "auth_type": AUTH_TYPE_BEARER,
            "token": token,
        }

    # 4. 加密写入
    try:
        _vault.store_credential(system, credential, key)
    except Exception as e:
        logger.error("bind 写入失败: user_id=%s system=%s error=%s", user_id, system, e)
        return f"❌ 绑定失败: {type(e).__name__}"

    _audit.append(user_id, "bind", f"绑定 {system} ({auth_type})", key)
    return f"✅ 已绑定 {system}（{auth_type} 认证）"


async def cmd_unlock(user_id: str, args: list[str]) -> str:
    """解锁 vault：/vault unlock <PIN>"""
    if not _vault.is_initialized():
        return f"❌ vault 未初始化，请先 {CMD_PREFIX} set-pin <PIN>"

    if len(args) < 1:
        return f"用法: {CMD_PREFIX} unlock <PIN>"

    pin = args[0]
    try:
        derived_key = _vault.verify_pin(pin)
    except BadPinError:
        logger.warning("user_id=%s PIN 校验失败", user_id)
        return "❌ PIN 错误"
    except FileNotFoundError:
        return f"❌ vault 未初始化，请先 {CMD_PREFIX} set-pin <PIN>"

    _session_cache.unlock(user_id, derived_key)

    _audit.append(user_id, "unlock", f"TTL={30 * 60}s", derived_key)
    ttl = _session_cache.get_ttl_remaining(user_id)
    return f"✅ vault 已解锁（{ttl // 60} 分钟后自动锁定）"


async def cmd_lock(user_id: str, args: list[str]) -> str:
    """立即锁定 vault：/vault lock"""
    if not _session_cache.is_unlocked(user_id):
        return "ℹ️ vault 已是锁定状态"

    key = _session_cache.get(user_id)
    if key:
        _audit.append(user_id, "lock", "主动锁定", key)
    else:
        logger.info("user_id=%s vault 锁定（无有效 key）", user_id)
    _session_cache.lock(user_id)
    return "✅ vault 已锁定"


async def cmd_list(user_id: str, args: list[str]) -> str:
    """列出 config.yaml 声明的系统及其绑定状态：/vault list"""
    configured = _get_configured_systems()
    bound = set(_vault.list_bound_systems())

    key = _session_cache.get(user_id)
    if key:
        _audit.append(user_id, "list", "列出系统状态", key)

    # 拿 config 里每个系统的 base_url
    try:
        try:
            from . import get_systems_config
        except ImportError:  # pragma: no cover
            from __init__ import get_systems_config  # type: ignore[no-redef]
        systems_cfg = get_systems_config()
    except Exception:
        systems_cfg = {}

    if not configured:
        return (
            "📋 支持的系统: (空)\n\n"
            "请在 config.yaml 的 plugins.entries.hermes-credential-vault.systems 下声明。"
        )

    lines = ["📋 支持的系统:"]
    for s in configured:
        url = systems_cfg.get(s, {}).get("base_url", "")
        url_tag = f"   → {url}" if url else ""
        if s in bound:
            lines.append(f"  ✅ (已绑定) {s}{url_tag}")
        else:
            lines.append(f"  ❌ (未绑定) {s}{url_tag}")

    # 底部：有未绑定项时展示 bind 命令
    if set(configured) - bound:
        lines.append("")
        lines.append("绑定命令:")
        lines.append(f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>'")
        lines.append(f"  {CMD_PREFIX} bind <system> bearer '<token>'")

    return "\n".join(lines)


async def cmd_revoke(user_id: str, args: list[str]) -> str:
    """吊销已绑定系统的凭证：/vault revoke <system>

    注意：仅删除本地加密凭证，用户仍需去系统后台吊销 token。
    """
    if len(args) < 1:
        return f"用法: {CMD_PREFIX} revoke <system>"

    system = args[0].lower()

    key = _session_cache.get(user_id)
    if not key:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    deleted = _vault.revoke_token(system)
    if not deleted:
        return f"❌ 系统 '{system}' 未绑定"

    _audit.append(user_id, "revoke", f"吊销 {system}", key)
    return f"✅ 已删除 {system} 本地凭证。⚠️ 请前往 {system} 后台手动吊销该 token"


async def cmd_status(user_id: str, args: list[str]) -> str:
    """查看 vault 状态：/vault status"""
    init = _vault.is_initialized()
    unlocked = _session_cache.is_unlocked(user_id)
    ttl = _session_cache.get_ttl_remaining(user_id)

    lines = ["📊 Vault 状态:"]
    lines.append(f" • 初始化: {'是' if init else '否'}")
    lines.append(f" • 解锁: {'是' if unlocked else '否'}")
    if unlocked and ttl is not None:
        lines.append(f" • 剩余有效时间: {ttl // 60} 分 {ttl % 60} 秒")

    systems = _vault.list_bound_systems()
    if systems:
        lines.append(f" • 已绑定: {', '.join(systems)}")
    else:
        lines.append(" • 已绑定: 无")

    return "\n".join(lines)


async def cmd_audit(user_id: str, args: list[str]) -> str:
    """查看审计日志：/vault audit"""
    key = _session_cache.get(user_id)
    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    try:
        entries = _audit.read_all(key)
    except Exception:
        return "❌ 读取审计日志失败（可能是密钥不匹配或数据损坏）"

    if not entries:
        return "📋 审计日志为空"

    lines = ["📋 审计日志 (最近 20 条):"]
    for entry in entries[-20:]:
        ts = entry.get("ts", "?")
        event = entry.get("event", "?")
        details = entry.get("details", "")
        lines.append(f" • [{ts}] {event}: {details}")

    return "\n".join(lines)


async def cmd_help(user_id: str, args: list[str]) -> str:
    """显示帮助信息：/vault help"""
    configured = _get_configured_systems()
    systems_line = ", ".join(configured) if configured else "(config.yaml 未声明任何系统)"
    return f"""📚 Credential Vault 使用指南

首次使用流程:
  {CMD_PREFIX} set-pin <PIN>                              # 设置 PIN（≥8位，含小写/大写/数字/符号）
  {CMD_PREFIX} unlock <PIN>                                # 解锁 vault（有效期 30 分钟）
  {CMD_PREFIX} bind <system> basic '<user>' '<pass>'       # 绑定 basic 认证凭证
  {CMD_PREFIX} bind <system> bearer '<token>'              # 绑定 bearer 认证凭证

常用命令:
  {CMD_PREFIX} unlock <PIN>                                # 解锁 vault
  {CMD_PREFIX} lock                                        # 立即锁定 vault
  {CMD_PREFIX} list                                        # 列出系统状态
  {CMD_PREFIX} bind <system> basic '<user>' '<pass>'       # basic 认证
  {CMD_PREFIX} bind <system> bearer '<token>'              # bearer 认证
  {CMD_PREFIX} revoke <system>                             # 删除本地凭证
  {CMD_PREFIX} status                                      # 查看状态
  {CMD_PREFIX} audit                                       # 查看审计日志
  {CMD_PREFIX} help                                        # 显示本帮助

可用系统（由 config.yaml 声明）: {systems_line}

📝 凭证字段引号规则:
  bind 命令中 username / password / token 必须用【单引号】'...' 包裹
    ✅ {CMD_PREFIX} bind jira basic 'yosef@example.com' 'MyP@ssw0rd!'
    ✅ {CMD_PREFIX} bind jira bearer 'ATATT3xFfGF0abc...'
    ❌ {CMD_PREFIX} bind jira basic yosef@example.com MyPassword    (裸写会被拒绝)
    ❌ {CMD_PREFIX} bind jira bearer "ATATT..."                     (双引号会被拒绝)
  单引号内除 ' 外的任何字符都会被原样保留（$、\\、!、# 等无需转义）

⚠️ 安全提示:
  - PIN 和凭证会短暂出现在飞书聊天中（飞书服务端保存），建议发完后长按撤回
  - vault 解锁后 30 分钟无操作自动锁定
  - 忘记 PIN 只能联系管理员删除 vault 目录重新设置
  - 密码里含单引号 ' 本身时，考虑改密码或联系管理员（当前实现不支持嵌套单引号）
"""


async def slash_command_handler(raw_args: str) -> Optional[str]:
    """/vault 命令的 register_command shim。

    在 gateway 场景下，实际拦截由 pre_gateway_dispatch hook 完成；
    此 handler 作为 CLI/TUI 场景的备选路径。
    """
    if not raw_args or not raw_args.strip():
        raw_args = "help"
    return f"请在飞书私聊中使用 {CMD_PREFIX} {raw_args} 命令"
