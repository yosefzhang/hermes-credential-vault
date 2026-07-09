"""Hermes credential vault plugin — 多工程师凭证隔离插件。

设计参考：~/.hermes/plans/credential-vault-design.md

核心防护原则：
- 凭证在磁盘上加密（AES-256-GCM + Argon2id）
- /vault 命令在 pre_gateway_dispatch hook 中拦截，不进 session_store
- Agent 通过 call_external_system 工具代调 API，token 从不进入 LLM 上下文
- 内存中的 derived_key 有 30min TTL，到期后覆写清零
"""

import logging
from pathlib import Path

from .constants import CMD_PREFIX
from .vault_core import VaultCore, SessionKeyCache
from .audit import AuditLog
from . import gateway_hook, commands, tools

logger = logging.getLogger(__name__)

# 全局单例（进程内共享）
_vault: VaultCore | None = None
_session_cache: SessionKeyCache | None = None
_audit: AuditLog | None = None

# 运行时系统声明缓存（由 config.yaml 决定 —— name -> {"base_url": ...}）
_systems_config: dict = {}
# v0.2.0: SSO providers 配置缓存
_sso_providers_config: dict = {}


def _load_plugin_config() -> dict:
    """读取 config.yaml 中 plugins.entries.hermes-credential-vault 配置段。

    失败时返回空 dict（插件将无可用系统，call_external_system 会拒绝所有调用）。
    """
    try:
        from hermes_cli.config import load_config
        cfg = load_config() or {}
        return ((cfg.get("plugins") or {}).get("entries") or {}).get(
            "hermes-credential-vault"
        ) or {}
    except Exception as exc:
        logger.warning("读取 config.yaml 失败: %s", exc)
        return {}


def _get_vault_dir(plugin_cfg: dict) -> Path:
    """决定 vault 存储目录。

    优先级：
      1. config.yaml → plugins.entries.hermes-credential-vault.storage_dir
         (支持 {profile} 占位符，支持 ~ 展开)
      2. 默认 ~/.config/hermes-credential-vault/<profile>-vault/
    """
    # 拿当前 profile 名（default / xiaokui / ...）
    try:
        from hermes_cli.profiles import get_active_profile_name
        profile = get_active_profile_name() or "default"
    except Exception:
        profile = "default"

    storage_dir = (plugin_cfg.get("storage_dir") or "").strip()
    if storage_dir:
        resolved = Path(storage_dir.replace("{profile}", profile)).expanduser()
        logger.info("vault 使用 config.yaml 自定义路径: %s", resolved)
        return resolved

    # 默认: ~/.config/hermes-credential-vault/<profile>-vault
    return Path.home() / ".config" / "hermes-credential-vault" / f"{profile}-vault"


def _normalize_systems(raw_systems) -> dict:
    """规范化 config.yaml 里的 systems 字段。

    可接受两种格式（尽量宽容）：
      systems:
        jira:
          base_url: https://xxx
      # 或（简写）
      systems:
        jira: https://xxx

    v0.2.0 新增可选字段（dict 形式才支持）：
      - auth: basic|bearer|sso_cookie（默认 basic/bearer 由 bind 时决定）
      - sso_provider: 引用 sso_providers 下的 provider 名（仅 auth=sso_cookie 有意义）

    非 https:// 开头的 base_url 会记 warning 但仍然保留。
    """
    result: dict = {}
    if not isinstance(raw_systems, dict):
        return result

    for name, spec in raw_systems.items():
        if not name or not isinstance(name, str):
            continue
        name_lower = name.strip().lower()

        extras: dict = {}
        if isinstance(spec, str):
            base_url = spec.strip()
        elif isinstance(spec, dict):
            base_url = str(spec.get("base_url", "")).strip()
            # 可选字段
            if spec.get("auth"):
                extras["auth"] = str(spec["auth"]).strip().lower()
            if spec.get("sso_provider"):
                extras["sso_provider"] = str(spec["sso_provider"]).strip().lower()
        else:
            logger.warning("systems.%s 配置格式非法（应为 string 或 dict），已跳过", name)
            continue

        if not base_url:
            logger.warning("systems.%s 缺少 base_url，已跳过", name)
            continue

        if not base_url.startswith(("http://", "https://")):
            logger.warning("systems.%s.base_url 未以 http(s):// 开头: %s", name, base_url)

        entry = {"base_url": base_url.rstrip("/")}
        entry.update(extras)
        result[name_lower] = entry

    return result


def _normalize_sso_providers(raw_providers) -> dict:
    """规范化 config.yaml 里的 sso_providers 字段。

    结构（每个 provider 必须是 dict）：
      sso_providers:
        quectel_sso:
          login_trigger_url: https://devops.quectel.com/devops/
          success_url_pattern: "**/devops/**"
          cookie_domain: .quectel.com
          form_selectors:
            username: 'input[placeholder="Please Enter Username"]'
            password: 'input[placeholder="Please Enter Password"]'
            submit: 'button:has-text("Log In")'
          token_cookie_name: quectel_token
    """
    result: dict = {}
    if not isinstance(raw_providers, dict):
        return result

    required_top = ("login_trigger_url", "success_url_pattern", "cookie_domain", "form_selectors")
    required_form = ("username", "password", "submit")

    for name, spec in raw_providers.items():
        if not name or not isinstance(name, str) or not isinstance(spec, dict):
            logger.warning("sso_providers.%s 配置非法，已跳过", name)
            continue
        name_lower = name.strip().lower()

        missing = [k for k in required_top if k not in spec]
        if missing:
            logger.warning(
                "sso_providers.%s 缺少必填字段 %s，已跳过", name_lower, missing
            )
            continue

        form = spec.get("form_selectors") or {}
        if not isinstance(form, dict) or any(k not in form for k in required_form):
            logger.warning(
                "sso_providers.%s.form_selectors 缺少 username/password/submit，已跳过",
                name_lower,
            )
            continue

        result[name_lower] = {
            "login_trigger_url": str(spec["login_trigger_url"]).strip(),
            "success_url_pattern": str(spec["success_url_pattern"]).strip(),
            "cookie_domain": str(spec["cookie_domain"]).strip(),
            "form_selectors": {
                "username": str(form["username"]),
                "password": str(form["password"]),
                "submit": str(form["submit"]),
            },
            "token_cookie_name": str(spec.get("token_cookie_name", "")).strip(),
        }

    return result


def get_systems_config() -> dict:
    """返回运行时系统声明字典（副本，防止调用方误改）。

    结构：{"jira": {"base_url": "https://...", "auth"?: "...", "sso_provider"?: "..."}, ...}
    """
    return {k: dict(v) for k, v in _systems_config.items()}


def get_sso_providers_config() -> dict:
    """返回运行时 SSO providers 配置字典（副本）。"""
    return {k: dict(v) for k, v in _sso_providers_config.items()}


def register(ctx):
    """Hermes plugin 入口 —— 注册所有工具、hooks、命令、skill。

    由 Hermes PluginManager 在加载插件时自动调用。
    """
    global _vault, _session_cache, _audit, _systems_config, _sso_providers_config

    plugin_cfg = _load_plugin_config()
    _systems_config = _normalize_systems(plugin_cfg.get("systems") or {})
    _sso_providers_config = _normalize_sso_providers(plugin_cfg.get("sso_providers") or {})
    if _systems_config:
        logger.info(
            "hermes-credential-vault 声明的系统: %s",
            ", ".join(sorted(_systems_config.keys())),
        )
    else:
        logger.warning(
            "config.yaml 未声明任何 systems，call_external_system 将拒绝所有调用。"
            " 请在 plugins.entries.hermes-credential-vault.systems 下声明系统名和 base_url。"
        )
    if _sso_providers_config:
        logger.info(
            "hermes-credential-vault 声明的 sso_providers: %s",
            ", ".join(sorted(_sso_providers_config.keys())),
        )

    vault_dir = _get_vault_dir(plugin_cfg)
    vault_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    _vault = VaultCore(vault_dir)
    _session_cache = SessionKeyCache()
    _audit = AuditLog(vault_dir / "audit.log.enc")

    # 把单例注入到子模块
    commands.set_context(_vault, _session_cache, _audit)
    tools.set_context(_vault, _session_cache, _audit)
    gateway_hook.set_context = lambda *a: None  # gateway_hook 不依赖这些单例

    # 注册 hooks
    ctx.register_hook("pre_gateway_dispatch", gateway_hook.pre_gateway_dispatch_hook)
    ctx.register_hook("transform_tool_result", tools.transform_tool_result_hook)

    # 注册 agent 工具（system 枚举 = config.yaml 声明的列表）
    ctx.register_tool(
        name="call_external_system",
        toolset="credential_vault",
        schema=tools.build_call_external_system_schema(list(_systems_config.keys())),
        handler=tools.call_external_system_handler,
        is_async=True,
    )

    # 注意：不注册 /vault 为 slash command（详见旧注释）
    # 参见 gateway/run.py:9553-9568 的 plugin_command 派发路径。

    # 注册使用手册 skill
    skills_dir = Path(__file__).parent / "skills"
    if skills_dir.exists():
        for child in skills_dir.iterdir():
            if not child.is_dir():
                continue
            skill_md = child / "SKILL.md"
            if skill_md.exists():
                ctx.register_skill(child.name, skill_md, description="Vault 使用指南")

    logger.info("hermes-credential-vault 已初始化 (vault_dir=%s)", vault_dir)
