"""v0.2.0 SSO session 数据模型 + 加解密单元测试。"""

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

# tests/ 目录跑，plugin 根加到 sys.path 由 conftest.py 完成
from vault_core import VaultCore, NotBoundError
from sso_runner import build_session_record


PIN = "TestPin!123"


@pytest.fixture
def vault_dir():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "vault"
        d.mkdir()
        yield d


@pytest.fixture
def initialized_vault(vault_dir):
    v = VaultCore(vault_dir)
    v.initialize_pin(PIN)
    key = v.verify_pin(PIN)
    yield v, key


class TestSessionStorage:
    """store_session / load_session / revoke_session / has_session round-trip 测试。"""

    def test_store_and_load_session(self, initialized_vault):
        vault, key = initialized_vault
        session_data = {
            "provider": "quectel_sso",
            "cookies": [
                {"name": "quectel_token", "value": "abc123", "domain": ".quectel.com"},
                {"name": "quectel_refresh_token", "value": "def456", "domain": ".quectel.com"},
            ],
            "created_at": 1000,
            "expires_at": 2000,
            "refreshed_at": None,
        }
        vault.store_session("quectel_sso", session_data, key)

        loaded = vault.load_session("quectel_sso", key)
        assert loaded == session_data

    def test_load_unbound_provider_raises(self, initialized_vault):
        vault, key = initialized_vault
        with pytest.raises(NotBoundError):
            vault.load_session("nonexistent", key)

    def test_has_session(self, initialized_vault):
        vault, key = initialized_vault
        assert not vault.has_session("quectel_sso")
        vault.store_session("quectel_sso", {"cookies": []}, key)
        assert vault.has_session("quectel_sso")

    def test_revoke_session(self, initialized_vault):
        vault, key = initialized_vault
        vault.store_session("quectel_sso", {"cookies": []}, key)
        assert vault.revoke_session("quectel_sso") is True
        assert not vault.has_session("quectel_sso")
        # 二次删除返回 False
        assert vault.revoke_session("quectel_sso") is False

    def test_list_sso_providers(self, initialized_vault):
        vault, key = initialized_vault
        assert vault.list_sso_providers() == []
        vault.store_session("quectel_sso", {"c": 1}, key)
        vault.store_session("another_sso", {"c": 2}, key)
        assert set(vault.list_sso_providers()) == {"quectel_sso", "another_sso"}

    def test_session_file_isolated_from_credential_scan(self, initialized_vault):
        """确保 .session.enc 不会被 list_bound_systems 误认为 basic/bearer 凭证。"""
        vault, key = initialized_vault
        # 存一个 basic 凭证
        vault.store_credential("jira", {"auth_type": "basic", "username": "u", "password": "p"}, key)
        # 存一个 SSO session
        vault.store_session("quectel_sso", {"cookies": []}, key)
        # list_bound_systems 只应看到 jira，看不到 quectel_sso
        assert vault.list_bound_systems() == ["jira"]
        # list_sso_providers 只应看到 quectel_sso
        assert vault.list_sso_providers() == ["quectel_sso"]

    def test_session_content_encrypted_on_disk(self, initialized_vault, vault_dir):
        """确保写入磁盘的 session 文件不是明文。"""
        vault, key = initialized_vault
        secret = "MEGA_SECRET_TOKEN_VALUE_ABC123"
        vault.store_session(
            "quectel_sso",
            {"cookies": [{"name": "quectel_token", "value": secret}]},
            key,
        )
        # 读原始文件字节
        enc_file = vault_dir / "quectel_sso.session.enc"
        raw = enc_file.read_bytes()
        assert secret.encode() not in raw, "session 文件不应包含明文 token"

    def test_wrong_key_cannot_decrypt(self, vault_dir):
        """PIN 错误 (key 不对) 无法解密 session。"""
        v1 = VaultCore(vault_dir)
        v1.initialize_pin(PIN)
        key1 = v1.verify_pin(PIN)
        v1.store_session("quectel_sso", {"cookies": [{"name": "x", "value": "y"}]}, key1)

        # 用一个假 key 尝试解密
        fake_key = bytearray(b"\x00" * 32)
        with pytest.raises(Exception):
            v1.load_session("quectel_sso", fake_key)


class TestBuildSessionRecord:
    """sso_runner.build_session_record 结构化逻辑测试。"""

    def test_basic_record_shape(self):
        cookies = [
            {"name": "quectel_token", "value": "abc", "expires": 2000000000},
            {"name": "quectel_refresh_token", "value": "def", "expires": 2000000000},
        ]
        record = build_session_record("quectel_sso", cookies, "quectel_token")
        assert record["provider"] == "quectel_sso"
        assert record["cookies"] == cookies
        assert record["expires_at"] == 2000000000
        assert record["refreshed_at"] is None
        assert isinstance(record["created_at"], int)
        assert record["created_at"] > 0

    def test_missing_token_cookie_yields_zero_expires(self):
        cookies = [{"name": "other_cookie", "value": "x", "expires": 12345}]
        record = build_session_record("quectel_sso", cookies, "quectel_token")
        assert record["expires_at"] == 0

    def test_session_cookie_no_expires_yields_zero(self):
        cookies = [{"name": "quectel_token", "value": "abc", "expires": -1}]
        record = build_session_record("quectel_sso", cookies, "quectel_token")
        # expires=-1 表示 session cookie，视为未知
        assert record["expires_at"] == 0

    def test_empty_cookies_list(self):
        record = build_session_record("quectel_sso", [], "quectel_token")
        assert record["cookies"] == []
        assert record["expires_at"] == 0
