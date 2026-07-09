"""gateway_hook.py 单元测试 —— pre_gateway_dispatch 拦截逻辑。"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Mock objects
# ============================================================================

class MockPlatform:
    """模拟 platform 枚举。"""
    def __init__(self, value):
        self.value = value


class MockSource:
    """模拟 MessageEvent.source。"""
    def __init__(
        self, user_id=None, chat_id=None, platform=None, chat_type=None
    ):
        self.user_id = user_id
        self.chat_id = chat_id
        self.platform = platform
        self.chat_type = chat_type


class MockEvent:
    """模拟 MessageEvent。"""
    def __init__(self, text="", source=None):
        self.text = text
        self.source = source


# ============================================================================
# 直接从 gateway_hook 导入辅助函数
# ============================================================================

from gateway_hook import _extract_user_id, _is_dm


class TestExtractHelpers:
    """提取 event 信息的辅助函数测试。"""

    def test_extract_user_id(self):
        event = MockEvent(source=MockSource(user_id="u123"))
        assert _extract_user_id(event) == "u123"

    def test_extract_user_id_none(self):
        event = MockEvent(source=MockSource())
        assert _extract_user_id(event) is None


class TestIsDM:
    """_is_dm 判断测试。"""

    def test_dm_by_chat_type(self):
        """chat_type="dm" → True。"""
        event = MockEvent(source=MockSource(chat_type="dm"))
        assert _is_dm(event) is True

    def test_dm_by_chat_type_private(self):
        """chat_type="private" → True。"""
        event = MockEvent(source=MockSource(chat_type="private"))
        assert _is_dm(event) is True

    def test_group_by_chat_type(self):
        """chat_type="group" → False。"""
        event = MockEvent(source=MockSource(chat_type="group"))
        assert _is_dm(event) is False

    def test_channel_by_chat_type(self):
        """chat_type="channel" → False。"""
        event = MockEvent(source=MockSource(chat_type="channel"))
        assert _is_dm(event) is False

    def test_dm_by_user_equals_chat(self):
        """user_id == chat_id → True。"""
        event = MockEvent(
            source=MockSource(user_id="same", chat_id="same")
        )
        assert _is_dm(event) is True

    def test_no_source_returns_false(self):
        """无 source → False（安全优先）。"""
        event = MockEvent()
        assert _is_dm(event) is False

    def test_no_chat_type_returns_false(self):
        """有 source 但无 chat_type → False（无法判断时拒绝）。"""
        event = MockEvent(source=MockSource())
        assert _is_dm(event) is False


class TestPreGatewayDispatchHook:
    """pre_gateway_dispatch 核心逻辑测试 —— 非异步部分。"""

    async def _run_hook(self, event, gateway=None, session_store=None):
        """调用 hook 并返回结果。hook 本身是同步的，此处 await 兼容原 async 测试写法。"""
        from gateway_hook import pre_gateway_dispatch_hook

        if gateway is None:
            gateway = _MockGateway()
        if session_store is None:
            session_store = object()

        # hook 是同步返回 dict，直接调用即可（不 await）
        return pre_gateway_dispatch_hook(
            event=event, gateway=gateway, session_store=session_store
        )

    @pytest.mark.asyncio
    async def test_non_vault_message_returns_none(self):
        """非 /vault 消息 → 返回 None（正常流程）。"""
        event = MockEvent(text="hello world", source=MockSource(user_id="u1", chat_type="dm"))
        result = await self._run_hook(event)
        assert result is None

    @pytest.mark.asyncio
    async def test_vault_message_returns_skip(self):
        """以 /vault 开头的消息 → 返回 {"action": "skip"}。"""
        event = MockEvent(text="/vault help", source=MockSource(user_id="u1", chat_type="dm"))
        result = await self._run_hook(event)
        assert result is not None
        assert result.get("action") == "skip"

    @pytest.mark.asyncio
    async def test_group_chat_blocked(self):
        """群聊中的 /vault → 返回 skip，sender 收到拒绝回复。"""
        import asyncio
        sent_messages = []

        class MockAdapter:
            async def send_message(self, chat_id, text):
                sent_messages.append(text)

        class RecordingGateway(_MockGateway):
            def __init__(self):
                self.adapters = {"feishu": MockAdapter()}

        event = MockEvent(
            text="/vault unlock 123",
            source=MockSource(
                user_id="u1",
                chat_id="g1",
                chat_type="group",
                platform=MockPlatform("feishu"),
            ),
        )
        result = await self._run_hook(event, gateway=RecordingGateway())
        assert result is not None
        assert result.get("action") == "skip"
        # 让 fire-and-forget task 有机会执行
        await asyncio.sleep(0)
        # 应有一条警告消息
        assert any("私聊" in m for m in sent_messages)

    @pytest.mark.asyncio
    async def test_no_user_id_returns_skip(self):
        """无法提取 user_id → 返回 skip。"""
        event = MockEvent(text="/vault help", source=MockSource())
        result = await self._run_hook(event)
        assert result is not None
        assert result.get("action") == "skip"

    @pytest.mark.asyncio
    async def test_vault_prefix_with_trailing(self):
        """以 /vault 开头（如 /vault bind jira ...）→ 返回 skip。"""
        event = MockEvent(
            text="/vault bind jira https://jira.example.com token123",
            source=MockSource(user_id="u1", chat_type="dm"),
        )
        result = await self._run_hook(event)
        assert result is not None
        assert result.get("action") == "skip"


# ============================================================================
# Mock Gateway（模拟 gateway 的 send_message）
# ============================================================================

class _MockGateway:
    """模拟 gateway 对象，提供 async send_message。"""

    async def send_message(self, platform, chat_id, text):
        pass
