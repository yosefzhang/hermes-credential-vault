"""pre_gateway_dispatch hook —— 拦截 /vault 消息，使其不入 session_store。

这是凭证保护的核心防线：/vault bind / unlock 等命令中可能包含 PIN/token，
必须在消息写入 session_store 之前拦截并处理。

关键实现细节：
- Hermes 的 invoke_hook 是**同步**调用（不 await 回调），因此 hook 函数
  必须是同步 def，不能用 async def，否则 gateway 拿到 coroutine 对象，
  .get("action") 会失败，然后被外层 try/except 静默吞掉。
- 参考 hermes-lark-streaming/aowen 的 handle_pre_gateway_dispatch 实现。
- 异步 IO（发消息、命令处理）用 asyncio.create_task fire-and-forget 到
  当前运行的事件循环。
"""

import asyncio
import logging
from typing import Optional

try:
    from .constants import CMD_PREFIX
    from .commands import dispatch_vault_command
except ImportError:
    from constants import CMD_PREFIX  # type: ignore[no-redef]
    from commands import dispatch_vault_command  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# 模块级全局引用 —— 让 tools.py 能反查 user_id
# 每次 hook 被调用时都会刷新（gateway/session_store 实例在进程内是长期稳定的）
_gateway_ref = None
_session_store_ref = None


def resolve_user_id_from_session_id(session_id: str) -> Optional[str]:
    """通过 session_store 反查 session_id 对应的 user_id。

    Hermes core 传给工具 handler 的 kwargs 只有 task_id / session_id / user_task，
    没有 user_id。SessionStore._entries 维护了 session_id → SessionEntry.origin.user_id
    的映射，这里做一次线性扫描（一般用户 session 数 < 10，性能可忽略）。

    Args:
        session_id: agent.session_id（形如 ``20260708_175447_7702b581``）

    Returns:
        用户身份字符串（形如飞书 ``ou_82b8...``），或 ``None`` 如果找不到
    """
    if not session_id or _session_store_ref is None:
        return None
    entries = getattr(_session_store_ref, "_entries", None)
    if not entries:
        return None
    try:
        for entry in entries.values():
            if getattr(entry, "session_id", None) == session_id:
                origin = getattr(entry, "origin", None)
                if origin is not None:
                    return getattr(origin, "user_id", None) or None
    except Exception as exc:
        logger.debug("resolve_user_id_from_session_id 遍历失败: %s", exc)
    return None


def _skip(reason: str) -> dict:
    """构造 pre_gateway_dispatch 的 skip 返回值。"""
    return {"action": "skip", "reason": reason}


def pre_gateway_dispatch_hook(event, gateway=None, session_store=None, **kwargs):
    """pre_gateway_dispatch hook 回调（同步）。

    Hermes gateway 在写入 session_store 之前触发此 hook。
    返回 {"action": "skip"} 让消息完全消失 —— 不进 session、memory、agent。

    Args:
        event: MessageEvent 对象
        gateway: GatewayRunner 实例（可选，某些调用点不传）
        session_store: session 存储对象（可选）

    Returns:
        {"action": "skip", "reason": "..."}  — 拦截并处理 /vault 命令
        None  — 不是 vault 命令，正常流程
    """
    # 保存全局引用，让 tools.py 能反查 user_id（每条消息都会调用，
    # 引用可能来自不同 profile 的 gateway，但同进程内实例是稳定的）
    global _gateway_ref, _session_store_ref
    if gateway is not None:
        _gateway_ref = gateway
    if session_store is not None:
        _session_store_ref = session_store

    try:
        text = getattr(event, "text", "") or ""
        text = text.strip()

        if not text.startswith(CMD_PREFIX):
            return None  # 不是 vault 命令，正常流程

        logger.info("vault: 收到命令 text=%s...", text[:20])

        # 提取信息
        user_id = _extract_user_id(event)

        if not user_id:
            logger.warning("vault: 无法提取 user_id，跳过")
            _fire_and_forget(lambda: _send_reply_async(gateway, event, "❌ 无法识别用户身份"))
            return _skip("no user_id")

        # 安全约束：只在 DM 中允许 /vault（禁止群聊）
        if not _is_dm(event):
            _fire_and_forget(lambda: _send_reply_async(gateway, event, "⚠️ /vault 命令只能在私聊中使用（禁止群聊）"))
            return _skip("vault command in group blocked")

        # 派发到 commands.py 处理 —— 异步任务，fire-and-forget
        async def _dispatch_and_reply():
            try:
                reply = await dispatch_vault_command(text, user_id, event)
            except Exception as e:
                logger.exception("vault: 处理命令异常 user_id=%s: %s", user_id[:12] if user_id else "?", e)
                reply = f"❌ 命令执行失败: {type(e).__name__}"
            await _send_reply_async(gateway, event, reply)

        _fire_and_forget(_dispatch_and_reply)

        return _skip("vault command handled")

    except Exception as exc:
        logger.exception("vault: pre_gateway_dispatch 未预期异常: %s", exc)
        # 即使异常也要 skip，防止敏感消息落入 agent
        return _skip(f"vault error: {type(exc).__name__}")


def _fire_and_forget(coro_fn):
    """把异步任务 fire-and-forget 到当前事件循环。"""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro_fn())
    except RuntimeError:
        logger.warning("vault: 没有 running event loop，跳过异步任务")


def _extract_user_id(event) -> Optional[str]:
    """从 MessageEvent 提取用户标识。"""
    source = getattr(event, "source", None)
    if source is None:
        return None
    return getattr(source, "user_id", None) or None


def _is_dm(event) -> bool:
    """判断消息是否来自私聊（DM）。安全优先：无法判断时默认拒绝。"""
    source = getattr(event, "source", None)
    if source is None:
        return False

    chat_type = getattr(source, "chat_type", None)
    if chat_type is not None:
        chat_type_str = str(chat_type).lower()
        if chat_type_str in ("dm", "private", "direct", "direct_message", "p2p"):
            return True
        return False

    user_id = getattr(source, "user_id", None)
    chat_id = getattr(source, "chat_id", None)
    if user_id and chat_id and user_id == chat_id:
        return True

    return False


async def _send_reply_async(gateway, event, text: str) -> None:
    """通过 gateway 发送回复消息给用户。

    尝试 2 种策略：
    1. gateway._adapter_for_source(source).send(chat_id, text)  ← Hermes 标准
    2. gateway.adapters[platform].send_message(chat_id, text)   ← 备选
    """
    if gateway is None:
        logger.warning("_send_reply: gateway is None")
        return

    source = getattr(event, "source", None)
    if source is None:
        logger.warning("_send_reply: event 缺少 source")
        return

    platform_name = getattr(source, "platform", None)
    platform_name = getattr(platform_name, "value", None) if platform_name else None
    chat_id = getattr(source, "chat_id", None)

    if not platform_name or not chat_id:
        logger.warning("_send_reply: 缺少 platform=%s 或 chat_id=%s", platform_name, chat_id)
        return

    # 策略 1: _adapter_for_source（Hermes 核心 API）
    adapter_for_source = getattr(gateway, "_adapter_for_source", None)
    if callable(adapter_for_source):
        try:
            adapter = adapter_for_source(source)
            if adapter and hasattr(adapter, "send"):
                result = adapter.send(chat_id, text)
                if asyncio.iscoroutine(result):
                    await result
                return
        except Exception as e:
            logger.debug("_adapter_for_source.send 失败: %s", e)

    # 策略 2: adapters dict
    adapters = getattr(gateway, "adapters", None) or getattr(gateway, "_adapters", None) or {}
    adapter = adapters.get(platform_name) if hasattr(adapters, "get") else None
    if adapter and hasattr(adapter, "send_message"):
        try:
            result = adapter.send_message(chat_id, text)
            if asyncio.iscoroutine(result):
                await result
            return
        except Exception as e:
            logger.debug("adapter.send_message 失败: %s", e)

    logger.error("vault: 所有发送策略均失败 platform=%s chat_id=%s", platform_name, chat_id)
