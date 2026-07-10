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
        AUTH_TYPE_SSO,
        AUTH_TYPE_SSO_COOKIE,  # 向后兼容别名
        SUPPORTED_AUTH_TYPES,
        SSO_REFRESH_THRESHOLD_SECONDS,
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
        AUTH_TYPE_SSO,
        AUTH_TYPE_SSO_COOKIE,
        SUPPORTED_AUTH_TYPES,
        SSO_REFRESH_THRESHOLD_SECONDS,
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

    # 子命令路由表（精简版）
    handlers = {
        "set-pin": cmd_set_pin,
        "bind": cmd_bind,
        "unbind": cmd_unbind,
        "unlock": cmd_unlock,
        "list": cmd_list,
        "help": cmd_help,
        # v0.2.0: SSO Session 管理
        "sso-login": cmd_sso_login,
        "sso-status": cmd_sso_status,
        "sso-logout": cmd_sso_logout,
        "providers": cmd_providers,
    }

    handler = handlers.get(subcommand)
    if handler is None:
        return f"❌ 未知命令: /vault {subcommand}\n输入 /vault help 查看可用命令"

    # === 统一安全前置检查 ===
    exempt_subcmds = {"set-pin", "help"}

    if subcommand not in exempt_subcmds:
        if not _vault.is_initialized():
            return f"❌ vault 未初始化，请先 {CMD_PREFIX} set-pin <PIN>"

        if subcommand != "unlock":
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
# bind 命令输入清洗
# ============================================================================

# Markdown 链接：[text](url) —— 飞书客户端会自动把邮箱格式化成这种形式
_MARKDOWN_LINK_RE = re.compile(r"^\[([^\]]+)\]\(([^)]+)\)$")


def _strip_markdown_link(value: str) -> tuple[str, bool]:
    """从 markdown 链接 [text](url) 中提取 text；不是链接则原样返回。

    返回 (clean_value, was_stripped)。
    按 Q1/Q2 决策：所有 [text](url) 都取 text，不区分 mailto/http/其他。
    """
    m = _MARKDOWN_LINK_RE.match(value.strip())
    if m is None:
        return value, False
    return m.group(1).strip(), True


# ============================================================================
# bind 命令引号校验
# ============================================================================

def _validate_bind_quotes(raw_text: str) -> Optional[str]:
    """强制 bind 命令的凭证字段（username/password/token）用单引号包裹。

    规则：
      /vault bind <system> basic '<username>' '<password>' <base_url>
      /vault bind <system> bearer '<token>' <base_url>
      /vault bind <system> sso <provider> <base_url>   # sso 类型无凭证需要包裹

    - 允许单引号 '...'
    - 禁止双引号 "..."（避免反斜杠转义歧义）
    - 禁止裸写（避免空格/特殊字符解析事故）
    - sso 类型不检查引号（参数是 provider 名，无凭证字段）

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
        f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>' <base_url>\n"
        f"  {CMD_PREFIX} bind <system> bearer '<token>' <base_url>\n"
        f"  {CMD_PREFIX} bind <system> sso <provider> <base_url>\n"
        "示例:\n"
        f"  {CMD_PREFIX} bind jira basic 'yosef@example.com' 'MyP@ssw0rd!' https://ticket.example.com\n"
        f"  {CMD_PREFIX} bind jira bearer 'ATATT3xFfGF0...' https://ticket.example.com\n"
        f"  {CMD_PREFIX} bind devops sso quectel_sso https://devops.example.com"
    )

    if auth_type == "basic":
        # 期望 2 个单引号段：'user' 'pass' + base_url
        pattern = r"^'([^']*)'\s+'([^']*)'\s+\S+\s*$"
        if not re.match(pattern, rest):
            return "❌ basic 认证的 username 和 password 必须用单引号 '...' 包裹。" + quote_hint

    elif auth_type == "bearer":
        # 期望 1 个单引号段：'token' + base_url
        pattern = r"^'([^']*)'\s+\S+\s*$"
        if not re.match(pattern, rest):
            return "❌ bearer 认证的 token 必须用单引号 '...' 包裹。" + quote_hint

    elif auth_type == "sso":
        # sso 类型不检查凭证引号（参数是 provider 名 + base_url）
        return None

    else:
        # 其他 auth_type 交给 cmd_bind 报错
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
    """返回所有已知 system（config.yaml 声明 + vault 绑定，排除 provider 名）。"""
    try:
        try:
            from . import get_systems_config
        except ImportError:
            from __init__ import get_systems_config  # type: ignore[no-redef]
        config_systems = set(get_systems_config().keys())
    except (ImportError, Exception):
        config_systems = set()
    vault_systems = set(_vault.list_bound_systems()) if _vault else set()
    try:
        from .sso_runner import list_sso_providers
    except ImportError:
        from sso_runner import list_sso_providers  # type: ignore[no-redef]
    provider_names = set(list_sso_providers())
    return sorted((config_systems | vault_systems) - provider_names)


async def cmd_bind(user_id: str, args: list[str]) -> str:
    """绑定凭证：
        /vault bind <system> basic '<username>' '<password>' <base_url>
        /vault bind <system> bearer '<token>' <base_url>
        /vault bind <system> sso <provider> <base_url>
        /vault bind <provider_name> basic '<username>' '<password>'

    若目标名称匹配内置 SSO provider 名，basic 绑定视为 provider 账密（多 system 共享）。
    """
    key = _session_cache.get(user_id)
    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    configured = _get_configured_systems()
    usage = (
        f"用法:\n"
        f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>' <base_url>\n"
        f"  {CMD_PREFIX} bind <system> bearer '<token>' <base_url>\n"
        f"  {CMD_PREFIX} bind <system> sso <provider> <base_url>\n"
        f"  {CMD_PREFIX} bind <provider_name> basic '<username>' '<password>'\n"
        f"📝 凭证字段必须用单引号 '...' 包裹（禁止双引号）\n"
        f"可用 system: {', '.join(configured) if configured else '(空)'}"
    )

    if len(args) < 2:
        return usage

    target = args[0].lower()
    auth_type = args[1].lower()

    # 是否为内置 SSO provider 名（用于 provider 账密绑定）
    try:
        from .sso_runner import list_sso_providers
    except ImportError:
        from sso_runner import list_sso_providers  # type: ignore[no-redef]
    is_provider = target in set(list_sso_providers())

    # 校验 auth_type
    if auth_type not in SUPPORTED_AUTH_TYPES:
        return (
            f"❌ 认证类型必须显式指定为 basic、bearer 或 sso，收到: '{auth_type}'\n\n{usage}"
        )

    # --force 检测（必须在最后，其他参数之前）
    force = "--force" in [a.lower() for a in args]
    clean_args = [a for a in args if a.lower() != "--force"]

    # ================================================================
    # 1. provider 账密绑定（target 是 SSO provider 名 + basic）
    # ================================================================
    if is_provider and auth_type == AUTH_TYPE_BASIC:
        if len(clean_args) < 4:
            return f"❌ provider basic 绑定需要 <username> <password>\n\n{usage}"
        username, password = clean_args[2], clean_args[3]
        if not username or not password:
            return "❌ username 和 password 不能为空"
        username, _stripped = _strip_markdown_link(username)
        if not username:
            return "❌ username 清洗后为空，请检查输入"

        credential = {"auth_type": AUTH_TYPE_BASIC, "username": username, "password": password}

        # 检查是否已有绑定
        try:
            _vault.load_credential(target, key)
            if not force:
                return (
                    f"⚠️ provider '{target}' 已有绑定的账密。\n"
                    f"  覆盖将删除旧凭证。确认请执行:\n"
                    f"  {CMD_PREFIX} bind {target} basic '<user>' '<pass>' --force"
                )
        except NotBoundError:
            pass

        try:
            _vault.store_credential(target, credential, key)
        except Exception as e:
            logger.error("bind provider 写入失败: %s error=%s", target, e)
            return f"❌ 绑定失败: {type(e).__name__}"

        _audit.append(user_id, "bind", f"绑定 provider {target} (basic)", key)
        return f"✅ 已为 SSO provider '{target}' 绑定账密"

    # ================================================================
    # 2. system 绑定（target 是 system 名）
    # ================================================================
    # 解析 base_url（最后一个参数必须是 http(s):// 开头）
    remaining = clean_args[2:] if len(clean_args) > 2 else []
    if not remaining or not remaining[-1].startswith(("http://", "https://")):
        return f"❌ 缺少 base_url，请在命令末尾添加系统 URL\n\n{usage}"
    base_url = remaining.pop().rstrip("/")

    # --- 按 auth_type 组装凭证 ---

    if auth_type == AUTH_TYPE_BASIC:
        if len(remaining) < 2:
            return f"❌ basic 认证需要 <username> <password>\n\n{usage}"
        username, password = remaining[0], remaining[1]
        if not username or not password:
            return "❌ username 和 password 不能为空"
        username, username_stripped = _strip_markdown_link(username)
        if not username:
            return "❌ username 清洗后为空，请检查输入"
        credential = {"auth_type": AUTH_TYPE_BASIC, "username": username, "password": password, "base_url": base_url}

    elif auth_type == AUTH_TYPE_BEARER:
        if len(remaining) < 1:
            return f"❌ bearer 认证需要 <token>\n\n{usage}"
        token = remaining[0]
        if not token:
            return "❌ token 不能为空"
        credential = {"auth_type": AUTH_TYPE_BEARER, "token": token, "base_url": base_url}
        username_stripped = False

    elif auth_type == AUTH_TYPE_SSO:
        if len(remaining) < 1:
            return f"❌ sso 认证需要 <provider>\n\n{usage}"
        provider = remaining[0].lower()
        # 校验 provider 存在于注册表
        try:
            from .sso_runner import get_sso_provider
        except ImportError:
            from sso_runner import get_sso_provider  # type: ignore[no-redef]
        if not get_sso_provider(provider):
            available = ", ".join(list_sso_providers())
            return (
                f"❌ SSO provider '{provider}' 未在插件注册表中找到。\n"
                f"  可用 provider: {available or '(空)'}\n"
                f"  如需新增，需要开发者修改 sso_runner.py 的 SSO_PROVIDERS 添加。"
            )
        credential = {"auth_type": AUTH_TYPE_SSO, "sso_provider": provider, "base_url": base_url}
        username_stripped = False

    else:
        return f"❌ 不支持的认证类型: {auth_type}\n\n{usage}"

    # --- 切换确认 ---
    try:
        existing = _vault.load_credential(target, key)
        existing_auth = (existing.get("auth_type") or "").lower()
        if existing_auth != auth_type and not force:
            return (
                f"⚠️ {target} 当前绑定为 {existing_auth} 认证。\n"
                f"  切换为 {auth_type} 将删除旧凭证。\n"
                f"  确认请执行: {CMD_PREFIX} bind {target} {auth_type}"
                f"{' ' + remaining[0] if remaining else ''}"
                f"{' ' + base_url if base_url else ''} --force"
            )
    except NotBoundError:
        pass  # 无旧绑定，直接写入
    except Exception:
        pass  # 读取失败，直接写入

    # --- 加密写入 ---
    try:
        _vault.store_credential(target, credential, key)
    except Exception as e:
        logger.error("bind 写入失败: user_id=%s target=%s error=%s", user_id, target, e)
        return f"❌ 绑定失败: {type(e).__name__}"

    _audit.append(user_id, "bind", f"绑定 {target} ({auth_type})", key)
    reply = f"✅ 已绑定 {target}（{auth_type} 认证）"
    if auth_type == AUTH_TYPE_SSO:
        reply += f"\nℹ️ 接下来执行 {CMD_PREFIX} sso-login {target} 触发 SSO 登录"
    elif auth_type == AUTH_TYPE_BASIC and username_stripped:
        reply += (
            f"\n⚠️ 检测到 username 被格式化为 markdown 链接，"
            f"已自动提取 `{credential['username']}`。\n"
            f"如提取结果不符预期，请 {CMD_PREFIX} unbind {target} 后重新 bind。"
        )
    return reply


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


async def cmd_list(user_id: str, args: list[str]) -> str:
    """列出 vault 状态及系统绑定状态：/vault list"""
    configured = _get_configured_systems()
    bound = set(_vault.list_bound_systems())

    key = _session_cache.get(user_id)
    if key:
        _audit.append(user_id, "list", "列出系统状态", key)

    # 状态信息（合并 status 功能）
    unlocked = key is not None
    ttl = _session_cache.get_ttl_remaining(user_id)

    lines = ["📊 Vault 状态:"]
    lines.append(f" • 解锁: {'是' if unlocked else '否'}")
    if unlocked and ttl is not None:
        lines.append(f" • 剩余有效时间: {ttl // 60} 分 {ttl % 60} 秒")
    lines.append("")

    # 拿 config 里每个系统的 base_url
    try:
        try:
            from . import get_systems_config
        except ImportError:  # pragma: no cover
            from __init__ import get_systems_config  # type: ignore[no-redef]
        systems_cfg = get_systems_config()
    except Exception:
        systems_cfg = {}

    # 已绑定的 provider
    try:
        from .sso_runner import list_sso_providers as _list_ssop
    except ImportError:
        from sso_runner import list_sso_providers as _list_ssop  # type: ignore[no-redef]
    provider_names = set(_list_ssop())
    bound_providers = bound & provider_names
    bound_systems = bound - provider_names

    lines.append("📋 系统列表:")
    for s in sorted(set(configured) | bound_systems):
        url = systems_cfg.get(s, {}).get("base_url", "")
        url_tag = f"   → {url}" if url else ""
        if s in bound_systems:
            lines.append(f"  ✅ (已绑定) {s}{url_tag}")
        else:
            lines.append(f"  ❌ (未绑定) {s}{url_tag}")

    if bound_providers:
        lines.append("")
        lines.append("📋 SSO Provider 账密:")
        for p in sorted(bound_providers):
            lines.append(f"  ✅ {p}")

    # 底部：展示 bind 命令
    unbound_systems = set(configured) - bound_systems
    if unbound_systems or not configured:
        lines.append("")
        lines.append("绑定命令:")
        lines.append(f"  {CMD_PREFIX} bind <system> basic '<username>' '<password>'")
        lines.append(f"  {CMD_PREFIX} bind <system> bearer '<token>'")
        lines.append(f"  {CMD_PREFIX} bind <system> sso <provider>")
        lines.append(f"  {CMD_PREFIX} bind <provider> basic '<user>' '<pass>'")

    return "\n".join(lines)


async def cmd_unbind(user_id: str, args: list[str]) -> str:
    """解绑 system：/vault unbind <system>"""
    if len(args) < 1:
        return f"用法: {CMD_PREFIX} unbind <system>"

    target = args[0].lower()
    key = _session_cache.get(user_id)
    if not key:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    # 检查是否是 provider
    try:
        from .sso_runner import list_sso_providers
    except ImportError:
        from sso_runner import list_sso_providers  # type: ignore[no-redef]
    if target in set(list_sso_providers()):
        bound = _vault.list_bound_systems()
        referencing = []
        for sys_name in bound:
            try:
                sys_cred = _vault.load_credential(sys_name, key)
                if sys_cred.get("auth_type") == AUTH_TYPE_SSO and sys_cred.get("sso_provider") == target:
                    referencing.append(sys_name)
            except Exception:
                pass
        if referencing:
            return (
                f"❌ provider '{target}' 被以下 system 引用: {', '.join(referencing)}\n"
                f"请先逐个 unbind 这些 system 后再尝试。"
            )

    deleted = _vault.revoke_token(target)
    if not deleted:
        return f"❌ '{target}' 未绑定任何凭证"
    _audit.append(user_id, "unbind", f"解绑 {target}", key)
    return f"✅ 已解绑 {target}"


async def cmd_providers(user_id: str, args: list[str]) -> str:
    """列出插件内置的 SSO providers：/vault providers"""
    try:
        from .sso_runner import list_sso_providers, get_sso_provider
    except ImportError:
        from sso_runner import list_sso_providers, get_sso_provider  # type: ignore[no-redef]
    providers = list_sso_providers()
    if not providers:
        return "📋 当前无内置 SSO provider"
    lines = ["📋 内置 SSO providers:"]
    for p in providers:
        cfg = get_sso_provider(p)
        url = (cfg or {}).get("login_trigger_url", "?")
        lines.append(f"  {p}")
        lines.append(f"    触发 URL: {url}")
    return "\n".join(lines)


async def cmd_help(user_id: str, args: list[str]) -> str:
    """显示帮助信息：/vault help"""
    configured = _get_configured_systems()
    systems_line = ", ".join(configured) if configured else "(config.yaml 未声明任何系统)"
    return f"""📚 Credential Vault 使用指南

首次使用流程:
  {CMD_PREFIX} set-pin <PIN>                              # 设置 PIN（≥8位，含小写/大写/数字/符号）
  {CMD_PREFIX} unlock <PIN>                                # 解锁 vault（有效期 30 分钟）
  {CMD_PREFIX} bind <system> basic '<user>' '<pass>' <url> # 绑定 basic 认证
  {CMD_PREFIX} bind <system> bearer '<token>' <url>        # 绑定 bearer 认证
  {CMD_PREFIX} bind <system> sso <provider> <url>          # 绑定 SSO 认证
  {CMD_PREFIX} bind <provider> basic '<user>' '<pass>'     # 存 SSO 登录账密（多 system 共享）

常用命令:
  {CMD_PREFIX} unlock <PIN>                                # 解锁 vault
  {CMD_PREFIX} list                                        # 查看状态及系统绑定
  {CMD_PREFIX} bind <system> basic '<user>' '<pass>' <url> # basic 认证
  {CMD_PREFIX} bind <system> bearer '<token>' <url>        # bearer 认证
  {CMD_PREFIX} bind <system> sso <provider> <url>          # SSO 认证
  {CMD_PREFIX} bind <provider> basic '<user>' '<pass>'     # 存 SSO 登录账密
  {CMD_PREFIX} unbind <system>                             # 解绑系统
  {CMD_PREFIX} providers                                   # 列出内置 SSO providers
  {CMD_PREFIX} help                                        # 显示本帮助

SSO 会话管理:
  {CMD_PREFIX} sso-login <system>                          # 用 provider 账密登录 SSO，产生 cookie 会话
  {CMD_PREFIX} sso-status [<system>]                       # 查看 SSO 会话状态
  {CMD_PREFIX} sso-logout <system>                         # 删除本地 SSO 会话
  💡 多个 system 共享同一个 sso_provider 时，一次 sso-login 覆盖所有关联 system。

可用系统: {systems_line}

📝 凭证字段引号规则:
  bind 命令中 username / password / token 必须用【单引号】'...' 包裹
    ✅ {CMD_PREFIX} bind jira basic 'yosef@example.com' 'MyP@ssw0rd!' https://ticket.example.com
    ✅ {CMD_PREFIX} bind jira bearer 'ATATT3xFfGF0abc...' https://ticket.example.com
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


# ============================================================================
# v0.3.0: SSO Session 管理子命令
# ============================================================================

def _get_systems_config_raw() -> dict:
    """读取 config.yaml 中 systems 配置段（由 __init__.py 缓存）。"""
    try:
        from . import get_systems_config
        return get_systems_config()
    except ImportError:
        try:
            from __init__ import get_systems_config
            return get_systems_config()
        except (ImportError, Exception):
            return {}  # 测试环境或 import 失败时返回空


def _list_sso_systems(key: Optional[bytes] = None) -> list[str]:
    """列出所有 auth=sso 的 system（config.yaml 声明 + vault 动态绑定）。

    当 key 提供时，对 vault 动态绑定的 system 解密检查 auth_type==sso；
    未提供 key 时（如 usage 提示），vault 来源的 system 不做过滤（稍宽松但无害）。
    """
    # config.yaml 来源
    config_sso = []
    for s, c in _get_systems_config_raw().items():
        if (c.get("auth") or "").lower() == AUTH_TYPE_SSO:
            config_sso.append(s)

    # vault 动态绑定来源
    vault_sso = []
    if _vault:
        try:
            from .sso_runner import list_sso_providers
        except ImportError:
            from sso_runner import list_sso_providers  # type: ignore[no-redef]
        provider_names = set(list_sso_providers())
        bound = _vault.list_bound_systems()
        for name in bound:
            if name in config_sso or name in provider_names:
                continue
            if key is not None:
                try:
                    cred = _vault.load_credential(name, key)
                    if cred.get("auth_type") == AUTH_TYPE_SSO:
                        vault_sso.append(name)
                except Exception:
                    pass
            else:
                # 无 key 时无法解密，直接纳入（usage 提示场景，稍宽松但无害）
                vault_sso.append(name)

    try:
        from .sso_runner import list_sso_providers
    except ImportError:
        from sso_runner import list_sso_providers  # type: ignore[no-redef]
    return sorted(set(config_sso) | set(vault_sso) - set(list_sso_providers()))


def _resolve_sso_system(system: str):
    """解析 system 的 SSO 配置，返回 (sys_cfg, provider_name, provider_cfg)。

    优先从 config.yaml 读取；若不存在则尝试从 vault 读取 system.enc。
    失败时返回 str 错误消息。
    """
    systems_cfg = _get_systems_config_raw()

    # Step 1: 确定 system 配置（config.yaml 优先）
    sys_cfg = {}
    if system in systems_cfg:
        sys_cfg = dict(systems_cfg[system])
    elif _vault and system in (set(_vault.list_bound_systems())):
        # 动态 vault 绑定 system，无 config.yaml 配置
        sys_cfg = {}
    else:
        sso_systems = _list_sso_systems()
        return (
            f"❌ system '{system}' 未绑定。\n"
            f"请先: {CMD_PREFIX} bind {system} sso <provider>\n"
            f"已注册 SSO system: {', '.join(sso_systems) if sso_systems else '(空)'}"
        )

    # Step 2: 确定 provider 名
    provider_name = sys_cfg.get("sso_provider", "")

    # Step 3: 从 sso_runner 注册表取 provider 配置
    try:
        from .sso_runner import get_sso_provider, list_sso_providers
    except ImportError:
        from sso_runner import get_sso_provider, list_sso_providers  # type: ignore[no-redef]

    if not provider_name:
        # 如 config.yaml 中有多个 SSO provider，取第一个
        providers = list_sso_providers()
        if len(providers) == 1:
            provider_name = providers[0]
        elif not providers:
            return "❌ 插件中未内置任何 SSO provider，请联系开发者添加。"
        else:
            return (
                f"❌ system '{system}' 未指定 sso_provider。\n"
                f"  可用 provider: {', '.join(providers)}\n"
                f"  请修改 config.yaml 添加 sso_provider 字段或执行 bind 时指定。"
            )

    provider_cfg = get_sso_provider(provider_name)
    if not provider_cfg:
        return (
            f"❌ SSO provider '{provider_name}' 未在插件注册表中找到。\n"
            f"  目前内置 provider: {', '.join(list_sso_providers()) or '(空)'}\n"
            f"  如需新增，需要开发者修改 sso_runner.py 的 SSO_PROVIDERS 添加。"
        )

    return sys_cfg, provider_name, provider_cfg


def _format_ttl(seconds: int) -> str:
    """把秒数格式化成 '3 天 5 小时' 或 '2 小时 30 分'。"""
    if seconds <= 0:
        return "已过期"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days > 0:
        return f"{days} 天 {hours} 小时"
    if hours > 0:
        return f"{hours} 小时 {minutes} 分"
    return f"{minutes} 分"


async def cmd_sso_login(user_id: str, args: list[str]) -> str:
    """执行 SSO 登录，把 cookie 集合加密存到 vault。

    用法：/vault sso-login <system>

    需要预先 /vault bind <provider_name> basic '<user>' '<pass>' 存过账密。
    多个 system 共享同一个 sso_provider 时，一次登录即可覆盖所有关联 system。
    """
    key = _session_cache.get(user_id)
    sso_systems = _list_sso_systems(key)
    if len(args) < 1:
        return (
            f"用法: {CMD_PREFIX} sso-login <system>\n"
            f"可用 SSO system: {', '.join(sso_systems) if sso_systems else '(空)'}"
        )

    system = args[0].lower()
    resolved = _resolve_sso_system(system)
    if isinstance(resolved, str):
        return resolved
    sys_cfg, provider, provider_cfg = resolved

    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    # 链式查找账密：先尝试 provider.enc（新格式），再回退 system.enc（旧格式兼容）
    username = ""
    password = ""
    legacy_compat = False

    try:
        # v0.3.0: 从 provider 账密取
        provider_cred = _vault.load_credential(provider, key)
        if provider_cred.get("auth_type") == AUTH_TYPE_BASIC:
            username = provider_cred.get("username") or ""
            password = provider_cred.get("password") or ""
    except NotBoundError:
        pass  # 回退到旧格式

    if not username or not password:
        # v0.2.0 兼容：从 system.enc 取 basic 账密
        try:
            old_cred = _vault.load_credential(system, key)
            if old_cred.get("auth_type") == AUTH_TYPE_BASIC:
                username = old_cred.get("username") or ""
                password = old_cred.get("password") or ""
                legacy_compat = True
        except NotBoundError:
            pass

        if not username or not password:
            # 都找不到，提示用户绑定 provider 账密
            return (
                f"❌ 未找到 SSO 登录凭证。\n"
                f"  请先绑定 SSO 账号: {CMD_PREFIX} bind {provider} basic '<user>' '<pass>'\n"
                f"  {f'并迁移旧凭证: {CMD_PREFIX} bind {system} sso {provider} --force' if not provider else ''}"
            )

    # 惰性 import sso_runner —— 避免装 Playwright 不用 SSO 的用户报错
    try:
        try:
            from .sso_runner import run_sso_login, build_session_record, SsoLoginError
        except ImportError:
            from sso_runner import run_sso_login, build_session_record, SsoLoginError  # type: ignore[no-redef]
    except Exception as e:
        return f"❌ SSO runner 加载失败: {type(e).__name__}: {e}"

    try:
        cookies = await run_sso_login(provider_cfg, username, password)
    except SsoLoginError as e:
        _audit.append(user_id, "sso_login_fail", f"{system} via {provider}: {e}", key)
        return f"❌ SSO 登录失败: {e}"
    except Exception as e:
        logger.exception("sso-login 未预期异常: %s", e)
        _audit.append(user_id, "sso_login_fail", f"{system} via {provider}: {type(e).__name__}", key)
        return f"❌ SSO 登录异常: {type(e).__name__}"
    finally:
        # 尽力清凭证引用
        username = ""
        password = ""

    if not cookies:
        return "❌ 登录成功但未获取到目标域 cookie，请检查 provider.cookie_domain 配置"

    token_cookie_name = provider_cfg.get("token_cookie_name", "")
    session_record = build_session_record(provider, cookies, token_cookie_name)
    # session 按 provider 存储 —— 覆盖所有共享该 provider 的 system
    _vault.store_session(provider, session_record, key)
    _audit.append(user_id, "sso_login_ok",
                  f"{system} via {provider} ({len(cookies)} cookies)", key)

    # 组装用户可见回执
    expires_at = session_record.get("expires_at") or 0
    import time as _time
    now = int(_time.time())
    ttl = expires_at - now if expires_at > 0 else 0
    ttl_line = (
        f"Token 有效期至: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(expires_at))}"
        f"（剩余 {_format_ttl(ttl)}）"
        if expires_at > 0 else "Token 有效期: 未知（session cookie）"
    )

    covered = sorted(_get_sso_covered_systems(provider, key).keys())
    cookie_names = ", ".join(c.get("name", "?") for c in cookies)
    reply = (
        f"✅ SSO 会话已建立\n"
        f"  触发 system: {system}\n"
        f"  覆盖 systems: {', '.join(covered)}\n"
        f"  Cookie 覆盖域: {provider_cfg.get('cookie_domain', '?')}（{len(cookies)} 个 cookie: {cookie_names}）\n"
        f"  {ttl_line}\n"
        f"下次 agent 访问上述 system 时会自动使用此会话。"
    )
    if legacy_compat:
        reply += (
            f"\n\n⚠️ 检测到旧格式凭证。建议迁移:\n"
            f"  1. {CMD_PREFIX} bind {provider} basic '<user>' '<pass>'   # 将账密绑定到 provider\n"
            f"  2. {CMD_PREFIX} bind {system} sso {provider} --force      # 更新 system 绑定\n"
            f"  3. {CMD_PREFIX} unbind {system}  # 删除旧 system 账密"
        )
    return reply


async def cmd_sso_status(user_id: str, args: list[str]) -> str:
    """查看 SSO session 状态：/vault sso-status [<system>]"""
    key = _session_cache.get(user_id)
    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    active = set(_vault.list_sso_providers())
    sso_systems = _list_sso_systems(key)

    if args:
        # 查单个 system
        system = args[0].lower()
        resolved = _resolve_sso_system(system)
        if isinstance(resolved, str):
            return resolved
        _, provider, _ = resolved

        if provider not in active:
            return (
                f"❌ system '{system}' 无有效 session（provider={provider} 未登录或已 sso-logout）\n"
                f"请执行 {CMD_PREFIX} sso-login {system}"
            )
        try:
            session = _vault.load_session(provider, key)
        except Exception as e:
            return f"❌ 读取 session 失败: {type(e).__name__}"

        import time as _time
        now = int(_time.time())
        expires_at = session.get("expires_at") or 0
        ttl = expires_at - now if expires_at > 0 else 0

        covered = sorted(_get_sso_covered_systems(provider, key).keys())
        lines = [
            f"📋 SSO Session (system={system}, provider={provider})",
            f"  覆盖 systems: {', '.join(covered)}",
            f"  Cookie 数量: {len(session.get('cookies', []))}",
            f"  创建时间: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(session.get('created_at', 0)))}",
        ]
        if expires_at > 0:
            lines.append(f"  过期时间: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(expires_at))}")
            lines.append(f"  剩余: {_format_ttl(ttl)}")
            if 0 < ttl < SSO_REFRESH_THRESHOLD_SECONDS:
                lines.append(f"  ⚠️ 即将过期，建议 {CMD_PREFIX} sso-login {system} 重新登录")
        else:
            lines.append("  过期时间: 未知（session cookie）")
        return "\n".join(lines)

    # 查全部 —— 按 SSO system 组织展示
    if not sso_systems:
        return "📋 未声明任何 auth=sso 的 system"

    lines = ["📋 SSO Systems 状态:"]
    import time as _time
    now = int(_time.time())
    systems_cfg = _get_systems_config_raw()
    for system in sso_systems:
        # 优先从 config.yaml 取 provider，其次从 vault 动态绑定
        if system in systems_cfg:
            provider = systems_cfg[system].get("sso_provider", "")
        else:
            provider = ""
            try:
                cred = _vault.load_credential(system, key)
                provider = cred.get("sso_provider", "")
            except Exception:
                pass
        if not provider:
            lines.append(f"  ❌ {system}: 无法确定 sso_provider")
            continue
        if provider in active:
            try:
                session = _vault.load_session(provider, key)
                expires_at = session.get("expires_at") or 0
                if expires_at > 0:
                    ttl = expires_at - now
                    mark = "⚠️" if 0 < ttl < SSO_REFRESH_THRESHOLD_SECONDS else "✅"
                    lines.append(f"  {mark} {system} (via {provider}): 剩余 {_format_ttl(ttl)}")
                else:
                    lines.append(f"  ✅ {system} (via {provider}): 已登录（session cookie，TTL 未知）")
            except Exception as e:
                lines.append(f"  ⚠️ {system} (via {provider}): session 读取失败 ({type(e).__name__})")
        else:
            lines.append(f"  ❌ {system} (via {provider}): 未登录（{CMD_PREFIX} sso-login {system}）")
    return "\n".join(lines)


async def cmd_sso_logout(user_id: str, args: list[str]) -> str:
    """删除本地 session：/vault sso-logout <system>

    ⚠️ 由于 session 按 provider 存储，logout 会踢下所有共享该 provider 的 system。
    """
    key = _session_cache.get(user_id)
    if len(args) < 1:
        return (
            f"用法: {CMD_PREFIX} sso-logout <system>\n"
            f"可用 SSO system: {', '.join(_list_sso_systems(key)) or '(空)'}"
        )

    system = args[0].lower()
    resolved = _resolve_sso_system(system)
    if isinstance(resolved, str):
        return resolved
    _, provider, _ = resolved

    if key is None:
        return f"❌ 请先 {CMD_PREFIX} unlock <PIN> 解锁 vault"

    covered = sorted(_get_sso_covered_systems(provider, key).keys())
    deleted = _vault.revoke_session(provider)
    if not deleted:
        return f"❌ system '{system}' (provider={provider}) 无 session 可删除"

    _audit.append(user_id, "sso_logout", f"{system} via {provider}", key)
    return (
        f"✅ 已删除 provider '{provider}' 的本地 session。\n"
        f"⚠️ 同时影响的 systems: {', '.join(covered)}\n"
        f"⚠️ 服务端 session 未主动通知，仍会自然过期。"
    )


def _get_sso_covered_systems(provider: str, key: Optional[bytes] = None) -> dict:
    """返回所有 auth=sso 且 sso_provider=<provider> 的 system 字典。

    合并两个来源：config.yaml 声明 + vault 动态绑定。
    """
    try:
        from . import get_systems_config
    except ImportError:  # pragma: no cover
        from __init__ import get_systems_config  # type: ignore[no-redef]
    all_systems = get_systems_config()
    result = {
        name: cfg
        for name, cfg in all_systems.items()
        if cfg.get("auth") == AUTH_TYPE_SSO
        and cfg.get("sso_provider") == provider
    }

    # vault 动态绑定来源
    if key is not None and _vault:
        try:
            from .sso_runner import list_sso_providers
        except ImportError:
            from sso_runner import list_sso_providers  # type: ignore[no-redef]
        provider_names = set(list_sso_providers())
        bound = _vault.list_bound_systems()
        for name in bound:
            if name in result or name in provider_names:
                continue
            try:
                cred = _vault.load_credential(name, key)
                if cred.get("auth_type") == AUTH_TYPE_SSO and cred.get("sso_provider") == provider:
                    result[name] = {
                        "base_url": cred.get("base_url", ""),
                        "auth": AUTH_TYPE_SSO,
                        "sso_provider": provider,
                    }
            except Exception:
                pass

    return result

