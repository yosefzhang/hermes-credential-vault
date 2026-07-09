"""内部系统 HTTP 客户端 —— 对配置声明的系统发起 REST API 调用。

使用 httpx.AsyncClient，认证方式由 credential["auth_type"] 决定：
  - basic:  HTTP Basic Auth (username + password)
  - bearer: Bearer Token
"""

import base64
import logging
from dataclasses import dataclass
from typing import Any

import httpx

try:
    from .constants import AUTH_TYPE_BASIC, AUTH_TYPE_BEARER
except ImportError:
    from constants import AUTH_TYPE_BASIC, AUTH_TYPE_BEARER  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# 通用超时
DEFAULT_TIMEOUT = 30.0


@dataclass
class Response:
    """HTTP 响应封装。"""
    status_code: int
    headers: dict[str, str]
    body: Any  # dict (JSON) 或 str


def _build_auth_header(credential: dict) -> str | None:
    """根据 credential dict 构造 Authorization header 值。

    Returns:
        Header 值字符串；参数不合法返回 None。
    """
    auth_type = (credential.get("auth_type") or "").lower()

    if auth_type == AUTH_TYPE_BASIC:
        username = credential.get("username") or ""
        password = credential.get("password") or ""
        if not username or not password:
            return None
        creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {creds}"

    if auth_type == AUTH_TYPE_BEARER:
        token = credential.get("token") or ""
        if not token:
            return None
        return f"Bearer {token}"

    return None


async def call_system(
    base_url: str,
    credential: dict,
    method: str,
    path: str,
    params: dict | None = None,
) -> Response:
    """统一入口：对任意声明的系统发起 HTTP 请求。

    Args:
        base_url: 系统 base URL（从 config.yaml 读取）
        credential: 已解密的凭证 dict（含 auth_type）
        method: HTTP 方法
        path: API 路径
        params: query params (GET) 或 JSON body (POST/PUT/PATCH)

    Returns:
        Response 对象
    """
    params = params or {}
    return await _http_call(
        base_url=base_url.rstrip("/"),
        credential=credential,
        method=method,
        path=path,
        params=params,
    )


async def _http_call(
    base_url: str,
    credential: dict,
    method: str,
    path: str,
    params: dict,
) -> Response:
    """底层 HTTP 请求。"""
    url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"

    auth_header = _build_auth_header(credential)
    if auth_header is None:
        return Response(
            400,
            {},
            {
                "error": "invalid_credential",
                "message": (
                    f"凭证 auth_type={credential.get('auth_type')} 校验失败，"
                    "请重新 /vault bind 该系统"
                ),
            },
        )

    headers = {
        "Authorization": auth_header,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        try:
            if method == "GET":
                resp = await client.get(url, headers=headers, params=params)
            elif method in ("POST", "PUT", "PATCH"):
                headers["Content-Type"] = "application/json"
                resp = await client.request(
                    method, url, headers=headers, json=params
                )
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                return Response(400, {}, {"error": f"不支持的 HTTP 方法: {method}"})
        except httpx.TimeoutException:
            logger.warning("HTTP 请求超时: %s %s", method, url)
            return Response(504, {}, {"error": "请求超时"})
        except httpx.RequestError as e:
            logger.warning("HTTP 请求失败: %s %s — %s", method, url, e)
            return Response(0, {}, {"error": f"请求失败: {e}"})

    try:
        body = resp.json()
    except Exception:
        body = resp.text

    return Response(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=body,
    )
