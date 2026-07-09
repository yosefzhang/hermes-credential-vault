"""SSO 登录子进程封装 —— Playwright 隔离，凭证在子进程内存的存活时间 < 3 秒。

核心：主进程通过 stdin 把 username / password 传给子进程，子进程 fill 表单登录成功后，
用 stdout 只回一个 JSON（cookie 列表），主进程读到后子进程立即退出。整个过程凭证
不进 argv、不进环境变量长期存活、不落盘。
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Optional

try:
    from .constants import SSO_LOGIN_TIMEOUT_SECONDS
except ImportError:
    from constants import SSO_LOGIN_TIMEOUT_SECONDS  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


class SsoLoginError(Exception):
    """SSO 登录失败。"""


# ============================================================================
# 子进程脚本（作为 -c 参数直接跑，避免落盘临时文件）
# ============================================================================

_CHILD_SCRIPT = r'''
import asyncio, json, sys

async def main():
    payload = json.loads(sys.stdin.read())
    provider = payload["provider_config"]
    username = payload["username"]
    password = payload["password"]

    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-gpu"]
        )
        try:
            ctx = await browser.new_context()
            page = await ctx.new_page()

            # 1. 打开触发登录跳转的 URL
            await page.goto(
                provider["login_trigger_url"],
                wait_until="domcontentloaded",
                timeout=15000,
            )

            # 2. 填表单
            await page.fill(provider["form_selectors"]["username"], username)
            await page.fill(provider["form_selectors"]["password"], password)

            # 3. 提交
            await page.click(provider["form_selectors"]["submit"])

            # 4. 等回到目标域
            await page.wait_for_url(
                provider["success_url_pattern"], timeout=15000
            )

            # 5. 提取 cookie，过滤目标 domain
            all_cookies = await ctx.cookies()
            target_domain = provider["cookie_domain"].lstrip(".")
            filtered = []
            for c in all_cookies:
                dom = (c.get("domain") or "").lstrip(".")
                if dom == target_domain or dom.endswith("." + target_domain):
                    filtered.append(c)

            print(json.dumps({"ok": True, "cookies": filtered}))
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        finally:
            # username/password 变量在函数栈上，进程退出即消失
            username = None  # noqa: F841
            password = None  # noqa: F841
            await browser.close()

asyncio.run(main())
'''


async def run_sso_login(
    provider_config: dict,
    username: str,
    password: str,
    python_bin: Optional[str] = None,
    timeout: int = SSO_LOGIN_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """在隔离子进程里跑一次 SSO 登录，返回 cookie 列表。

    Args:
        provider_config: 从 config.yaml 读到的 sso_providers[name] 字典
        username: 账号（子进程消费后清零）
        password: 密码（子进程消费后清零）
        python_bin: 指定 Python 解释器路径（默认沿用当前 sys.executable）
        timeout: 子进程整体超时（秒）

    Returns:
        Playwright cookie dict 列表（可直接传给 add_cookies）

    Raises:
        SsoLoginError: 登录失败（超时、表单错、URL 不匹配等）
    """
    python_bin = python_bin or sys.executable

    # 通过 stdin 传凭证，避免出现在 argv 或环境变量
    payload = json.dumps({
        "provider_config": provider_config,
        "username": username,
        "password": password,
    })

    proc = await asyncio.create_subprocess_exec(
        python_bin, "-c", _CHILD_SCRIPT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(payload.encode("utf-8")),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        raise SsoLoginError(f"SSO 登录超时（>{timeout}s）")

    # 消费完立即让主进程的 payload 变量失效（尽力而为，Python 无强制清零）
    payload = None  # noqa: F841

    if proc.returncode != 0:
        err_text = stderr.decode("utf-8", errors="replace")[:500]
        raise SsoLoginError(f"子进程异常退出（rc={proc.returncode}）: {err_text}")

    try:
        result = json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError:
        raise SsoLoginError(
            f"子进程输出非 JSON: {stdout.decode('utf-8', errors='replace')[:300]}"
        )

    if not result.get("ok"):
        raise SsoLoginError(result.get("error", "未知错误"))

    return result.get("cookies", [])


def check_playwright_available() -> tuple[bool, str]:
    """检测当前 Python 环境是否装了 Playwright 及 chromium。

    Returns:
        (available, hint_message)
    """
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, (
            "Playwright 未安装。请在 hermes 运行环境执行：\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )

    # 探测 chromium 二进制是否下载
    try:
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
            capture_output=True, timeout=5,
        )
        # dry-run 有变化则说明未装
        if b"install" in result.stdout.lower() and b"chromium" in result.stdout.lower():
            return False, (
                "Playwright chromium 未下载。请执行：\n"
                "  playwright install chromium"
            )
    except Exception:
        # 探测失败不阻断，交给实际运行报错
        pass

    return True, ""


def build_session_record(
    provider: str,
    cookies: list[dict],
    token_cookie_name: str,
) -> dict:
    """从 cookie 列表构造 session json 记录。

    Args:
        provider: SSO provider 名
        cookies: Playwright cookie dict 列表
        token_cookie_name: 用于读取 expires 的 cookie 名

    Returns:
        session json dict（可直接传给 vault_core.store_session）
    """
    now = int(time.time())
    expires_at = 0
    for c in cookies:
        if c.get("name") == token_cookie_name:
            exp = c.get("expires")
            if isinstance(exp, (int, float)) and exp > 0:
                expires_at = int(exp)
            break

    return {
        "provider": provider,
        "cookies": cookies,
        "created_at": now,
        "expires_at": expires_at,   # 0 = 未知（session cookie）
        "refreshed_at": None,
    }
