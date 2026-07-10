"""Agent 工具 —— call_external_system + transform_tool_result 兜底脱敏。

提供 agent 可调用的 call_external_system 工具（代 agent 调外部系统 API，
token 永远只在插件进程栈上短暂存活，不进入 agent/session/memory/LLM）。
"""

import copy
import json
import logging
import re
from typing import Optional

try:
    from .audit import AuditLog
    from .constants import (
        TOKEN_PATTERNS,
        AUTH_TYPE_SSO,
    )
    from .system_clients import call_system, call_system_with_cookies
    from .vault_core import VaultCore, SessionKeyCache, NotBoundError
except ImportError:
    from audit import AuditLog  # type: ignore[no-redef]
    from constants import (  # type: ignore[no-redef]
        TOKEN_PATTERNS,
        AUTH_TYPE_SSO,
    )
    from system_clients import call_system, call_system_with_cookies  # type: ignore[no-redef]
    from vault_core import VaultCore, SessionKeyCache, NotBoundError  # type: ignore[no-redef]


def _get_systems_config() -> dict:
    """运行时读取 __init__.py 里的 systems 字典（config.yaml 决定）。"""
    try:
        from . import get_systems_config
    except ImportError:  # pragma: no cover
        from __init__ import get_systems_config  # type: ignore[no-redef]
    return get_systems_config()

logger = logging.getLogger(__name__)

# 模块级单例（由 __init__.py 注入）
_vault: Optional[VaultCore] = None
_session_cache: Optional[SessionKeyCache] = None
_audit: Optional[AuditLog] = None


def set_context(vault: VaultCore, cache: SessionKeyCache, audit: AuditLog) -> None:
    """注入模块级单例。"""
    global _vault, _session_cache, _audit
    _vault = vault
    _session_cache = cache
    _audit = audit


# ============================================================================
# call_external_system 工具
# ============================================================================

CALL_EXTERNAL_SYSTEM_SCHEMA_TEMPLATE = {
    "name": "call_external_system",
    "description": (
        "Call an internal enterprise system's REST API on behalf of the current user. "
        "The credential is fetched from the user's encrypted vault and injected on the wire; "
        "the token itself is never returned — only the API response body. "
        "The list of available systems is declared in config.yaml and can be discovered via /vault help."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "system": {
                "type": "string",
                "enum": [],  # populated at register() time
                "description": "Target system (declared in config.yaml systems section)",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "description": "HTTP method",
            },
            "path": {
                "type": "string",
                "description": "API path, e.g. /rest/api/2/issue/JIRA-1234",
            },
            "params": {
                "type": "object",
                "description": "Query params for GET, JSON body for POST/PUT/PATCH",
                "additionalProperties": True,
            },
        },
        "required": ["system", "method", "path"],
    },
}


def build_call_external_system_schema(system_names: list[str]) -> dict:
    """基于 config.yaml 声明的系统列表构造 tool schema。"""
    schema = copy.deepcopy(CALL_EXTERNAL_SYSTEM_SCHEMA_TEMPLATE)
    schema["parameters"]["properties"]["system"]["enum"] = list(system_names)
    if system_names:
        schema["parameters"]["properties"]["system"]["description"] = (
            f"Target system. Available: {', '.join(system_names)}"
        )
    return schema


# 需要在工具返回值中过滤的敏感 header（避免意外泄露 token）
_SENSITIVE_HEADERS = {
    "set-cookie", "authorization", "x-api-key",
    "cookie", "x-auth-token", "api-key",
}


def _filter_headers(headers: dict) -> dict:
    """剔除可能包含 token 的敏感 header。"""
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _SENSITIVE_HEADERS
    }


async def call_external_system_handler(args: dict, **kwargs) -> str:
    """Agent 视角的入口：代 agent 调外部系统 API。

    流程：
    1. 从 kwargs 提取 user_id
    2. 检查 vault 解锁状态
    3. 解密 token（明文只存活在函数栈上）
    4. 调用 HTTP API
    5. 返回业务数据，token 从不外传
    """
    # 提取 user_id（Hermes 在不同路径下传的字段名不同）
    user_id = (
        kwargs.get("user_id")
        or ""
    )

    # Fallback：Hermes core 传下来的 kwargs 里没有 user_id，用 session_id 反查
    # session_store 里 SessionEntry.origin.user_id 才是真正的用户身份
    if not user_id:
        session_id = kwargs.get("session_id", "") or ""
        try:
            from .gateway_hook import resolve_user_id_from_session_id
            user_id = resolve_user_id_from_session_id(session_id) or ""
        except Exception as _exc:
            logger.debug("resolve_user_id_from_session_id 失败: %s", _exc)

    # 最终 fallback：task_id（保留兼容，避免完全无 user_context 时的 crash）
    if not user_id:
        user_id = kwargs.get("task_id") or ""

    if not user_id:
        return json.dumps(
            {
                "error": "no_user_context",
                "message": "无法识别当前用户，请从飞书私聊调用",
            },
            ensure_ascii=False,
        )

    system = args.get("system", "").lower()
    method = args.get("method", "GET").upper()
    path = args.get("path", "")
    params = args.get("params") or {}

    # 只处理 config.yaml 中声明的系统；未声明的直接拒绝，让 agent 明白本插件不管
    systems_cfg = _get_systems_config()
    if system not in systems_cfg:
        return json.dumps(
            {
                "error": "system_not_declared",
                "message": (
                    f"system '{system}' 未在 config.yaml 中声明，本插件不管理该系统。"
                    f"已声明的系统: {', '.join(sorted(systems_cfg.keys())) or '(空)'}"
                ),
            },
            ensure_ascii=False,
        )

    base_url = systems_cfg.get(system, {}).get("base_url", "")
    system_auth = (systems_cfg.get(system, {}).get("auth") or "").lower()
    sso_provider = systems_cfg.get(system, {}).get("sso_provider", "")

    # 1. 检查 vault 解锁
    key = _session_cache.get(user_id)
    if not key:
        return json.dumps(
            {
                "error": "vault_locked",
                "message": "vault 未解锁或已超时，请在飞书私聊发送 /vault unlock <PIN>",
            },
            ensure_ascii=False,
        )

    # 动态 system：从 vault 读取 base_url / auth_type / sso_provider
    if system not in systems_cfg or (not system_auth and not base_url):
        try:
            dyn_cred = _vault.load_credential(system, key)
            if not base_url:
                base_url = dyn_cred.get("base_url", "")
            if not system_auth:
                system_auth = (dyn_cred.get("auth_type") or "").lower()
                sso_provider = dyn_cred.get("sso_provider", "")
        except (NotBoundError, Exception):
            return json.dumps(
                {
                    "error": "system_not_found",
                    "message": (
                        f"系统 '{system}' 未配置。"
                        f"请先 bind: /vault bind {system} basic|bearer|sso ..."
                    ),
                },
                ensure_ascii=False,
            )

    if not base_url:
        return json.dumps(
            {
                "error": "no_base_url",
                "message": f"系统 '{system}' 未配置 base_url，无法发起 API 调用。",
            },
            ensure_ascii=False,
        )

    # 2a. SSO Cookie 路径
    if system_auth == AUTH_TYPE_SSO:
        if not sso_provider:
            return json.dumps(
                {
                    "error": "misconfigured_system",
                    "message": f"system '{system}' 声明 auth=sso 但缺少 sso_provider 字段",
                },
                ensure_ascii=False,
            )
        try:
            session = _vault.load_session(sso_provider, key)
        except NotBoundError:
            return json.dumps(
                {
                    "error": "sso_not_logged_in",
                    "message": (
                        f"system '{system}' 需要 SSO 登录（provider={sso_provider}）。"
                        f"请在飞书私聊发送 /vault sso-login {system}"
                    ),
                },
                ensure_ascii=False,
            )
        cookies = session.get("cookies") or []

        _audit.append(user_id, "api_call", f"{system} {method} {path} [sso:{sso_provider}]", key)

        resp = await call_system_with_cookies(base_url, cookies, method, path, params)
        return json.dumps(
            {
                "status_code": resp.status_code,
                "headers": _filter_headers(resp.headers),
                "body": resp.body,
            },
            ensure_ascii=False,
            default=str,
        )

    # 2b. basic / bearer 路径（v0.1.x 逻辑）
    # 解密凭证（明文只在本函数栈上存在）
    try:
        credential = _vault.load_credential(system, key)
    except NotBoundError:
        return json.dumps(
            {
                "error": "not_bound",
                "message": (
                    f"未绑定 {system}，请在飞书私聊发送 "
                    f"/vault bind {system} basic <user> <pass> 或 "
                    f"/vault bind {system} bearer <token>"
                ),
            },
            ensure_ascii=False,
        )

    auth_type = (credential.get("auth_type") or "").lower()

    # 3. 记审计（不记 token/密码）
    _audit.append(user_id, "api_call", f"{system} {method} {path} [{auth_type}]", key)

    # 4. 调用 API
    resp = await call_system(base_url, credential, method, path, params)

    # 5. 清除凭证引用（str 不可变，只能删除 key 让 GC 回收）
    for k in list(credential.keys()):
        credential[k] = ""
    credential.clear()
    del credential

    return json.dumps(
        {
            "status_code": resp.status_code,
            "headers": _filter_headers(resp.headers),
            "body": resp.body,
        },
        ensure_ascii=False,
        default=str,
    )


# ============================================================================
# transform_tool_result hook —— 兜底脱敏
# ============================================================================

_compiled_patterns = [re.compile(p) for p in TOKEN_PATTERNS]


def transform_tool_result_hook(result: str, tool_name: str, **kwargs) -> Optional[str]:
    """对 call_external_system 的返回值做正则扫描，意外出现 token 类字串则脱敏。

    这是架构防护之外的兜底措施：理论上 call_external_system_handler
    不会泄露 token，但以防万一（比如下游 API 错误地回显了 token）。
    """
    if tool_name != "call_external_system":
        return None

    if not result:
        return None

    redacted = result
    for pattern in _compiled_patterns:
        redacted = pattern.sub("[REDACTED]", redacted)

    if redacted != result:
        logger.warning("transform_tool_result: 在 call_external_system 返回值中发现疑似 token，已脱敏")
        return redacted

    return None
