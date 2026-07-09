"""vault_core.py 单元测试 —— PIN 管理、加解密回环、SessionKeyCache TTL。"""

import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_core import (
    VaultCore,
    SessionKeyCache,
    BadPinError,
    WeakPinError,
    NotBoundError,
    AlreadyInitializedError,
    _validate_pin_strength,
    _zero_bytes,
    _derive_key,
    _encrypt_and_write,
    _decrypt_file,
)
from constants import VERIFY_FILE, SALT_FILE


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def vault():
    """创建一个临时目录中的 VaultCore 实例。"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield VaultCore(Path(tmpdir))


@pytest.fixture
def initialized_vault(vault):
    """已初始化 PIN 的 vault。"""
    vault.initialize_pin("TestVault@2026!")
    return vault


@pytest.fixture
def cache():
    """创建一个 SessionKeyCache 实例。"""
    return SessionKeyCache()


# ============================================================================
# VaultCore —— PIN 管理
# ============================================================================

class TestPinManagement:
    """PIN 初始化与校验测试。"""

    def test_initial_state(self, vault):
        """新 vault 未初始化。"""
        assert not vault.is_initialized()

    def test_initialize_pin_success(self, vault):
        """正常初始化：PIN 设置后 is_initialized() 为 True，salt 和 verify 文件存在。"""
        vault.initialize_pin("TestVault@2026!")
        assert vault.is_initialized()
        assert (vault._vault_dir / SALT_FILE).exists()
        assert (vault._vault_dir / VERIFY_FILE).exists()

    def test_initialize_twice_raises(self, initialized_vault):
        """重复初始化应抛 AlreadyInitializedError。"""
        with pytest.raises(AlreadyInitializedError):
            initialized_vault.initialize_pin("OtherPIN@2026!")

    def test_verify_pin_success(self, initialized_vault):
        """正确 PIN 校验成功，返回 32 字节 bytearray key。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        assert isinstance(key, bytearray)
        assert len(key) == 32

    def test_verify_pin_wrong(self, initialized_vault):
        """错误 PIN 应抛 BadPinError。"""
        with pytest.raises(BadPinError):
            initialized_vault.verify_pin("WrongPIN@2026!")

    def test_verify_pin_not_initialized(self, vault):
        """未初始化的 vault 校验 PIN 应抛 FileNotFoundError。"""
        with pytest.raises(FileNotFoundError):
            vault.verify_pin("AnyPIN@2026!")


# ============================================================================
# VaultCore —— PIN 强度校验
# ============================================================================

class TestPinStrength:
    """PIN 强度校验测试（规则：≥8 位 + 小写/大写/数字/符号 4 类全含 + 无空白）。"""

    def test_weak_pin_too_short(self):
        """PIN 太短 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="长度"):
            _validate_pin_strength("Ab1!xy")  # 6 位

    def test_weak_pin_no_lower(self):
        """缺少小写字母 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="小写"):
            _validate_pin_strength("ABCD1234!")

    def test_weak_pin_no_upper(self):
        """缺少大写字母 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="大写"):
            _validate_pin_strength("abcd1234!")

    def test_weak_pin_no_digit(self):
        """缺少数字 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="数字"):
            _validate_pin_strength("Abcdefgh!")

    def test_weak_pin_no_symbol(self):
        """缺少符号 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="符号"):
            _validate_pin_strength("Abcd1234")

    def test_weak_pin_with_whitespace(self):
        """含空白字符 → WeakPinError。"""
        with pytest.raises(WeakPinError, match="空白"):
            _validate_pin_strength("Ab 1!cde")

    def test_strong_pin_all_four(self):
        """4 类齐全 → 通过。"""
        _validate_pin_strength("MyPass@2026!")
        _validate_pin_strength("aA1!bcde")
        _validate_pin_strength("XyZ#7890abc")


# ============================================================================
# VaultCore —— Token 加解密回环
# ============================================================================

class TestCredentialStore:
    """凭证存储回环测试。"""

    def test_store_and_load(self, initialized_vault):
        """存储 → 读取回环：加密再解密应得到原始数据。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        cred_in = {"auth_type": "bearer", "token": "my-secret-token-123"}
        initialized_vault.store_credential("jira", cred_in, key)
        credential = initialized_vault.load_credential("jira", key)
        assert credential["auth_type"] == "bearer"
        assert credential["token"] == "my-secret-token-123"

    def test_store_and_load_basic(self, initialized_vault):
        """basic 认证结构化存取。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        cred_in = {"auth_type": "basic", "username": "u@x.com", "password": "P@ss"}
        initialized_vault.store_credential("jira", cred_in, key)
        credential = initialized_vault.load_credential("jira", key)
        assert credential == cred_in

    def test_load_not_bound(self, initialized_vault):
        """读取未绑定的系统 → NotBoundError。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        with pytest.raises(NotBoundError):
            initialized_vault.load_credential("confluence", key)

    def test_revoke(self, initialized_vault):
        """吊销后读取应抛 NotBoundError。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        initialized_vault.store_credential("jira", {"auth_type": "bearer", "token": "tok"}, key)
        assert initialized_vault.revoke_token("jira") is True
        with pytest.raises(NotBoundError):
            initialized_vault.load_credential("jira", key)

    def test_revoke_nonexistent(self, initialized_vault):
        """吊销未绑定的系统返回 False。"""
        assert initialized_vault.revoke_token("nonexistent") is False

    def test_list_bound(self, initialized_vault):
        """list_bound_systems 返回已绑定系统名，不含 token。"""
        key = initialized_vault.verify_pin("TestVault@2026!")
        initialized_vault.store_credential("jira", {"auth_type": "bearer", "token": "tok"}, key)
        initialized_vault.store_credential("confluence", {"auth_type": "bearer", "token": "tok"}, key)
        systems = initialized_vault.list_bound_systems()
        assert "jira" in systems
        assert "confluence" in systems

    def test_list_bound_excludes_audit_log(self, initialized_vault):
        """list_bound_systems 必须排除 audit.log.enc（它是审计日志，不是系统凭证）。"""
        from audit import AuditLog
        key = initialized_vault.verify_pin("TestVault@2026!")
        # 触发 audit.log.enc 创建
        vault_dir = initialized_vault._vault_dir
        audit = AuditLog(vault_dir / "audit.log.enc")
        audit.append("u1", "unlock", "test", key)
        # 再存一个真实系统凭证
        initialized_vault.store_credential("jira", {"auth_type": "bearer", "token": "t"}, key)
        systems = initialized_vault.list_bound_systems()
        assert systems == ["jira"]
        assert "audit.log" not in systems

    def test_encryption_is_different_with_different_keys(self, initialized_vault):
        """不同 PIN 派生的 key 无法解密对方的密文。"""
        v2 = VaultCore(initialized_vault._vault_dir)
        # 注意：v2 共享同一目录但 has 不同的 salt，
        # 我们需要一个新的 vault 目录来测试跨 key 隔离
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            v1 = VaultCore(Path(td))
            v1.initialize_pin("PinOne@2026!")
            k1 = v1.verify_pin("PinOne@2026!")
            v1.store_credential("jira", {"auth_type": "bearer", "token": "secret1"}, k1)

            # 模拟攻击者用错误 key 解密
            from vault_core import _zero_bytes
            import os
            salt = (Path(td) / SALT_FILE).read_bytes()
            from vault_core import _derive_key
            wrong_key = _derive_key("PinTwo@2026!", salt)
            with pytest.raises(Exception):
                v1.load_credential("jira", wrong_key)


# ============================================================================
# SessionKeyCache
# ============================================================================

class TestSessionKeyCache:
    """SessionKeyCache TTL 与滑动过期测试。"""

    def test_unlock_and_get(self, cache):
        """unlock → get 获取 key。"""
        key = b"a" * 32
        cache.unlock("user1", key)
        assert cache.is_unlocked("user1")
        assert cache.get("user1") == key

    def test_get_unknown_user(self, cache):
        """未解锁的 user_id 返回 None。"""
        assert cache.get("unknown") is None
        assert not cache.is_unlocked("unknown")

    def test_ttl_remaining(self, cache):
        """get_ttl_remaining 返回剩余秒数。"""
        cache.unlock("user1", b"a" * 32)
        remaining = cache.get_ttl_remaining("user1")
        assert remaining is not None
        assert remaining > 0

    def test_lock_clears_key(self, cache):
        """lock 后 get 返回 None。"""
        cache.unlock("user1", b"a" * 32)
        cache.lock("user1")
        assert cache.get("user1") is None

    def test_expired_key_returns_none(self, cache, monkeypatch):
        """过期 key 返回 None。"""
        now = time.time()
        # 设置过去的 TTL
        cache.unlock("user1", b"a" * 32)
        with cache._lock:
            cache._store["user1"]["expires_at"] = now - 10  # 已过期 10 秒
        assert cache.get("user1") is None

    def test_sliding_expiration(self, cache, monkeypatch):
        """get 命中时刷新 TTL（滑动过期）。"""
        cache.unlock("user1", b"a" * 32)
        time.sleep(0.1)
        key = cache.get("user1")
        assert key is not None
        # TTL 应该被刷新
        remaining = cache.get_ttl_remaining("user1")
        assert remaining is not None
        # 刷新后应接近 30min
        assert remaining >= 1790  # 至少 29 分 50 秒

    def test_lock_after_expired_silent(self, cache):
        """lock 已过期的用户不抛异常。"""
        cache.unlock("user1", b"a" * 32)
        with cache._lock:
            cache._store["user1"]["expires_at"] = 0
        cache.lock("user1")  # 不应抛异常
        assert cache.get("user1") is None


# ============================================================================
# 内部工具函数
# ============================================================================

class TestInternalUtils:
    """内部工具函数测试。"""

    def test_derive_key_deterministic(self):
        """相同 PIN + salt 产生相同 key。"""
        salt = b"x" * 16
        k1 = _derive_key("pin", salt)
        k2 = _derive_key("pin", salt)
        assert k1 == k2

    def test_derive_key_different(self):
        """不同 PIN 产生不同 key。"""
        salt = b"x" * 16
        k1 = _derive_key("pin1", salt)
        k2 = _derive_key("pin2", salt)
        assert k1 != k2

    def test_zero_bytes_actually_zeros(self):
        """_zero_bytes 对 bytearray 执行原地清零。"""
        buf = bytearray(b"secret data here!!")
        _zero_bytes(buf)
        assert buf == bytearray(b"\x00" * 18)

    def test_zero_bytes_ignores_bytes(self):
        """_zero_bytes 对不可变 bytes 不抛异常（静默跳过）。"""
        _zero_bytes(b"test data")  # 不抛异常即为通过
