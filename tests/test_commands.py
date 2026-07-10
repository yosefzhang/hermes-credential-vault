"""commands.py 单元测试 —— 子命令逻辑（新版：显式 auth_type + config.yaml 系统声明）。"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_core import VaultCore, SessionKeyCache, _validate_pin_strength
from audit import AuditLog


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def vault():
    """临时 vault。"""
    with tempfile.TemporaryDirectory() as td:
        v = VaultCore(Path(td))
        v.initialize_pin("TestVault@2026!")
        yield v


@pytest.fixture
def cache():
    """临时 SessionKeyCache。"""
    return SessionKeyCache()


@pytest.fixture
def audit():
    """临时 AuditLog。"""
    with tempfile.TemporaryDirectory() as td:
        yield AuditLog(Path(td) / "audit.log.enc")


@pytest.fixture(autouse=True)
def inject_modules(vault, cache, audit, monkeypatch):
    """注入模块级单例，并 stub 系统声明列表。"""
    import commands
    commands.set_context(vault, cache, audit)

    # 让 _get_configured_systems 返回稳定的测试列表（不依赖 config.yaml）
    monkeypatch.setattr(
        commands,
        "_get_configured_systems",
        lambda: ["jira", "confluence"],
    )


# ============================================================================
# set-pin
# ============================================================================

class TestCmdSetPin:

    @pytest.mark.asyncio
    async def test_weak_pin_rejected(self):
        """弱 PIN 被拒绝（使用未初始化的 vault）。"""
        import commands as cmd_mod
        from vault_core import VaultCore
        with tempfile.TemporaryDirectory() as td:
            v = VaultCore(Path(td))
            old_vault = cmd_mod._vault
            try:
                cmd_mod._vault = v
                result = await cmd_mod.cmd_set_pin("user1", ["abc"])
                assert "❌" in result or "强度" in result
            finally:
                cmd_mod._vault = old_vault

    @pytest.mark.asyncio
    async def test_already_initialized(self):
        """已初始化的 vault 拒绝 set-pin。"""
        import commands
        result = await commands.cmd_set_pin("user1", ["NewPass@2027!"])
        assert "已初始化" in result


# ============================================================================
# bind（新语法）
# ============================================================================

class TestCmdBind:

    @pytest.mark.asyncio
    async def test_bind_when_locked(self):
        """vault 未解锁时拒绝 bind。"""
        import commands
        result = await commands.cmd_bind("user1", ["jira", "basic", "u", "p"])
        assert "请先" in result
        assert "unlock" in result

    @pytest.mark.asyncio
    async def test_bind_undeclared_system(self):
        """system 未在 config.yaml 中声明 → 拒绝。"""
        import commands
        from commands import _session_cache
        _session_cache.unlock("user1", b"a" * 32)
        result = await commands.cmd_bind("user1", ["github", "bearer", "tok"])
        assert "无法确定" in result

    @pytest.mark.asyncio
    async def test_bind_missing_auth_type(self):
        """缺少认证类型（arg 只有 system） → 用法提示。"""
        import commands
        from commands import _session_cache
        _session_cache.unlock("user1", b"a" * 32)
        result = await commands.cmd_bind("user1", ["jira"])
        assert "用法" in result

    @pytest.mark.asyncio
    async def test_bind_invalid_auth_type(self):
        """认证类型必须显式为 basic/bearer，其他拒绝。"""
        import commands
        from commands import _session_cache
        _session_cache.unlock("user1", b"a" * 32)
        result = await commands.cmd_bind("user1", ["jira", "oauth", "xxx"])
        assert "basic" in result and "bearer" in result

    @pytest.mark.asyncio
    async def test_bind_bearer_success(self, vault):
        """bearer 认证正常绑定。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("user1", key)
        result = await commands.cmd_bind("user1", ["jira", "bearer", "mytoken123", "https://jira.example.com"])
        assert "✅" in result
        assert "bearer" in result
        assert _vault.list_bound_systems() == ["jira"]
        # 验证结构化存储
        cred = _vault.load_credential("jira", key)
        assert cred["auth_type"] == "bearer"
        assert cred["token"] == "mytoken123"

    @pytest.mark.asyncio
    async def test_bind_basic_success(self, vault):
        """basic 认证正常绑定，存储 auth_type + username + password。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("user1", key)
        result = await commands.cmd_bind(
            "user1", ["jira", "basic", "yosef@example.com", "MyP@ssw0rd", "https://jira.example.com"]
        )
        assert "✅" in result
        assert "basic" in result
        cred = _vault.load_credential("jira", key)
        assert cred["auth_type"] == "basic"
        assert cred["username"] == "yosef@example.com"
        assert cred["password"] == "MyP@ssw0rd"
        # 千万不能有旧 token 字段
        assert "token" not in cred

    @pytest.mark.asyncio
    async def test_bind_basic_missing_password(self, vault):
        """basic 只给 username 缺 password → 拒绝。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("user1", key)
        result = await commands.cmd_bind("user1", ["jira", "basic", "user_only"])
        assert "❌" in result

    @pytest.mark.asyncio
    async def test_bind_bearer_missing_token(self, vault):
        """bearer 缺 token → 拒绝。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("user1", key)
        result = await commands.cmd_bind("user1", ["jira", "bearer"])
        assert "❌" in result


# ============================================================================
# unlock / lock
# ============================================================================

class TestCmdUnlock:

    @pytest.mark.asyncio
    async def test_unlock_wrong_pin(self):
        import commands
        result = await commands.cmd_unlock("user1", ["WrongPIN@2026!"])
        assert "❌" in result
        assert "PIN" in result

    @pytest.mark.asyncio
    async def test_unlock_success(self, vault):
        import commands
        from commands import _session_cache
        result = await commands.cmd_unlock("user1", ["TestVault@2026!"])
        assert "✅" in result
        assert _session_cache.is_unlocked("user1")


# ============================================================================
# list
# ============================================================================

class TestCmdList:

    @pytest.mark.asyncio
    async def test_list_empty(self):
        """无绑定系统 + 有声明 → 每个系统显示 (未绑定)。"""
        import commands
        result = await commands.cmd_list("user1", [])
        assert "未绑定" in result
        assert "jira" in result
        assert "confluence" in result

    @pytest.mark.asyncio
    async def test_list_does_not_contain_credentials(self, vault):
        """list 返回值不含 token / 密码。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _vault.store_credential(
            "jira",
            {"auth_type": "bearer", "token": "SECRET_TOKEN_123"},
            key,
        )
        _session_cache.unlock("user1", key)
        result = await commands.cmd_list("user1", [])
        assert "jira" in result
        assert "已绑定" in result
        assert "SECRET_TOKEN_123" not in result
        assert "SECRET" not in result

    @pytest.mark.asyncio
    async def test_list_bound_and_unbound_mix(self, vault):
        """混合状态：一个已绑定，一个未绑定。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _vault.store_credential(
            "jira",
            {"auth_type": "basic", "username": "u", "password": "p"},
            key,
        )
        _session_cache.unlock("user1", key)
        result = await commands.cmd_list("user1", [])
        # jira 已绑定
        assert "✅ (已绑定) jira" in result
        # confluence 未绑定
        assert "❌ (未绑定) confluence" in result

    @pytest.mark.asyncio
    async def test_list_ignores_orphan_credentials(self, vault, monkeypatch):
        """vault 里有但 config 未声明 → 直接不显示（新版极简策略）。"""
        import commands
        from commands import _session_cache, _vault
        # config 声明为空
        monkeypatch.setattr(commands, "_get_configured_systems", lambda: [])
        key = _vault.verify_pin("TestVault@2026!")
        _vault.store_credential(
            "old-sys",
            {"auth_type": "bearer", "token": "tok"},
            key,
        )
        _session_cache.unlock("user1", key)
        result = await commands.cmd_list("user1", [])
        # config 为空但 vault 有绑定 → 展示 vault 中的 system
        assert "old-sys" in result  # 新行为：展示 vault 绑定的 system


# ============================================================================
# help
# ============================================================================

class TestCmdHelp:

    @pytest.mark.asyncio
    async def test_help_shows_commands(self):
        import commands
        result = await commands.cmd_help("user1", [])
        assert "使用指南" in result
        assert "set-pin" in result
        assert "unlock" in result
        assert "bind" in result
        assert "basic" in result
        assert "bearer" in result


# ============================================================================
# dispatch
# ============================================================================

class TestDispatch:

    @pytest.mark.asyncio
    async def test_unknown_command(self):
        import commands
        result = await commands.dispatch_vault_command("/vault foobar", "u1", None)
        assert "未知" in result

    @pytest.mark.asyncio
    async def test_empty_subcommand_shows_help(self):
        import commands
        result = await commands.dispatch_vault_command("/vault", "u1", None)
        assert "使用指南" in result

    @pytest.mark.asyncio
    async def test_gate_locked_bind_rejected(self):
        """dispatch 层前置检查：未 unlock 时 bind 被拒。"""
        import commands
        result = await commands.dispatch_vault_command(
            "/vault bind jira bearer tok", "u1", None
        )
        assert "未解锁" in result or "unlock" in result

    @pytest.mark.asyncio
    async def test_gate_locked_list_rejected(self):
        """未 unlock 时 list 被拒。"""
        import commands
        result = await commands.dispatch_vault_command("/vault list", "u1", None)
        assert "未解锁" in result or "unlock" in result

    @pytest.mark.asyncio
    async def test_gate_status_always_allowed(self):
        """status 无需 unlock 即可查询。"""
        import commands
        result = await commands.dispatch_vault_command("/vault status", "u1", None)
        # 不能被前置检查拦住
        assert "未解锁或已超时" not in result

    @pytest.mark.asyncio
    async def test_gate_help_always_allowed(self):
        """help 无需 unlock。"""
        import commands
        result = await commands.dispatch_vault_command("/vault help", "u1", None)
        assert "使用指南" in result

    @pytest.mark.asyncio
    async def test_gate_uninitialized_rejects_unlock(self, monkeypatch):
        """未初始化时 unlock 被拒。"""
        import commands
        # stub vault 未初始化
        import commands as cmd_mod
        from vault_core import VaultCore
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            v = VaultCore(Path(td))  # 未 initialize
            old = cmd_mod._vault
            try:
                cmd_mod._vault = v
                result = await commands.dispatch_vault_command(
                    "/vault unlock SomePIN@2026!", "u1", None
                )
                assert "未初始化" in result
            finally:
                cmd_mod._vault = old


class TestBindQuoteEnforcement:
    """dispatch 层强制 bind 凭证字段用单引号。"""

    @pytest.mark.asyncio
    async def test_bearer_naked_rejected(self, vault):
        """bearer token 不加引号 → 拒绝。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            "/vault bind jira bearer ATATT3xxxxxxxxxx", "u1", None
        )
        assert "单引号" in result
        assert "❌" in result

    @pytest.mark.asyncio
    async def test_bearer_double_quote_rejected(self, vault):
        """bearer 用双引号 → 拒绝。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            '/vault bind jira bearer "ATATT3xxxxxxxxxx"', "u1", None
        )
        assert "单引号" in result

    @pytest.mark.asyncio
    async def test_bearer_single_quote_accepted(self, vault):
        """bearer 单引号 → 通过。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            "/vault bind jira bearer 'ATATT3xxxxxxxxxx' 'https://jira.example.com'", "u1", None
        )
        assert "✅" in result
        cred = _vault.load_credential("jira", key)
        assert cred["token"] == "ATATT3xxxxxxxxxx"

    @pytest.mark.asyncio
    async def test_basic_naked_rejected(self, vault):
        """basic 裸写 username/password → 拒绝。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            "/vault bind jira basic yosef@example.com password", "u1", None
        )
        assert "单引号" in result
        assert "❌" in result

    @pytest.mark.asyncio
    async def test_basic_mixed_quote_rejected(self, vault):
        """basic 只对 password 加单引号（username 裸写）→ 拒绝（因为要求两个都加）。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            "/vault bind jira basic yosef@example.com 'password'", "u1", None
        )
        assert "单引号" in result

    @pytest.mark.asyncio
    async def test_basic_both_single_quote_accepted(self, vault):
        """basic 两字段都单引号 → 通过。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        result = await commands.dispatch_vault_command(
            "/vault bind jira basic 'yosef@example.com' 'MyP@$$w0rd!' 'https://jira.example.com'", "u1", None
        )
        assert "✅" in result
        cred = _vault.load_credential("jira", key)
        assert cred["username"] == "yosef@example.com"
        assert cred["password"] == "MyP@$$w0rd!"

    @pytest.mark.asyncio
    async def test_basic_special_chars_in_single_quote(self, vault):
        """单引号内特殊字符（$, \\, !, #, ; 等）原样保留。"""
        import commands
        from commands import _session_cache, _vault
        key = _vault.verify_pin("TestVault@2026!")
        _session_cache.unlock("u1", key)
        weird_password = 'p@$$w0rd!#;&|\\path'
        result = await commands.dispatch_vault_command(
            f"/vault bind jira basic 'u' '{weird_password}' 'https://jira.example.com'", "u1", None
        )
        assert "✅" in result
        cred = _vault.load_credential("jira", key)
        assert cred["password"] == weird_password
