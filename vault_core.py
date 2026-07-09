"""加密核心 —— KDF + AES-256-GCM + SessionKeyCache。

提供 VaultCore 类（加密存储凭证）和 SessionKeyCache 类（内存 TTL 缓存）。
所有敏感数据操作均在此模块内完成，不外泄。
"""

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Optional

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from .constants import (
        AES_NONCE_LEN,
        ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM,
        ARGON2_TIME_COST,
        CLEANUP_INTERVAL_SECONDS,
        ENC_EXT,
        KEY_LEN,
        PIN_MIN_LENGTH,
        SALT_LEN,
        SALT_FILE,
        SESSION_ENC_SUFFIX,
        SESSION_TTL_SECONDS,
        VERIFY_FILE,
        VERIFY_PLAINTEXT,
    )
except ImportError:
    from constants import (  # type: ignore[no-redef]
        AES_NONCE_LEN,
        ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM,
        ARGON2_TIME_COST,
        CLEANUP_INTERVAL_SECONDS,
        ENC_EXT,
        KEY_LEN,
        PIN_MIN_LENGTH,
        SALT_LEN,
        SALT_FILE,
        SESSION_ENC_SUFFIX,
        SESSION_TTL_SECONDS,
        VERIFY_FILE,
        VERIFY_PLAINTEXT,
    )

logger = logging.getLogger(__name__)


# ============================================================================
# 异常类
# ============================================================================

class VaultError(Exception):
    """vault 基础异常。"""
    pass


class BadPinError(VaultError):
    """PIN 校验失败。"""
    pass


class NotBoundError(VaultError):
    """系统未绑定（.enc 文件不存在）。"""
    pass


class VaultLockedError(VaultError):
    """vault 未解锁（SessionKeyCache 中没有该用户的 key）。"""
    pass


class WeakPinError(VaultError):
    """PIN 强度不足（不满足复杂度要求）。"""
    pass


class AlreadyInitializedError(VaultError):
    """vault 已经初始化过（.verify 文件已存在）。"""
    pass


# ============================================================================
# VaultCore —— 加密存储核心
# ============================================================================

class VaultCore:
    """加密凭证存储：PIN 管理 + Token 加密存取。

    存储布局（以 vault_dir 为例）：
        vault_dir/
        ├── .salt          # 16 字节随机盐（明文）
        ├── .verify        # 用当前 PIN key 加密的固定字符串
        ├── jira.enc       # AES-256-GCM({"token":..., "base_url":...})
        ├── confluence.enc
        └── pms.enc
    """

    def __init__(self, vault_dir: Path):
        self._vault_dir = vault_dir

    # -------- PIN 管理 --------

    def is_initialized(self) -> bool:
        """检查 .verify 文件是否存在。"""
        return (self._vault_dir / VERIFY_FILE).exists()

    def initialize_pin(self, pin: str) -> None:
        """首次设置 PIN：验证强度 → 生成 salt → 写 .verify。

        Raises:
            AlreadyInitializedError: vault 已初始化
            WeakPinError: PIN 不满足强度要求
        """
        if self.is_initialized():
            raise AlreadyInitializedError("vault 已初始化，请勿重复设置 PIN")

        _validate_pin_strength(pin)

        salt = os.urandom(SALT_LEN)
        derived_key = _derive_key(pin, salt)

        self._vault_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        _write_file(self._vault_dir / SALT_FILE, salt)
        _encrypt_and_write(derived_key, VERIFY_PLAINTEXT, self._vault_dir / VERIFY_FILE)

        # 内存清零
        _zero_bytes(derived_key)

    def verify_pin(self, pin: str) -> bytearray:
        """校验 PIN 并返回派生的 32 字节 AES key（bytearray，支持原地清零）。

        读取 .salt → 用 PIN 派生 key → 解密 .verify → 比对固定字符串。

        Returns:
            派生的 32 字节 AES-256 密钥（bytearray）

        Raises:
            FileNotFoundError: vault 未初始化（.salt 或 .verify 不存在）
            BadPinError: PIN 错误
        """
        salt = _read_file(self._vault_dir / SALT_FILE)
        derived_key = _derive_key(pin, salt)

        try:
            plaintext = _decrypt_file(derived_key, self._vault_dir / VERIFY_FILE)
        except Exception:
            _zero_bytes(derived_key)
            raise BadPinError("PIN 校验失败：无法解密验证文件")

        if plaintext != VERIFY_PLAINTEXT:
            _zero_bytes(derived_key)
            raise BadPinError("PIN 错误")

        return derived_key

    # -------- Token 加密存取 --------

    def store_credential(
        self, system: str, credential: dict, derived_key: bytes
    ) -> None:
        """加密存储凭证 dict 到 <system>.enc 文件。

        credential 必须包含 auth_type，以及对应的字段：
            - auth_type == "basic":  {"auth_type": "basic", "username": ..., "password": ...}
            - auth_type == "bearer": {"auth_type": "bearer", "token": ...}

        Args:
            system: 系统名（jira / confluence / ...）
            credential: 结构化凭证 dict（已由调用方校验）
            derived_key: 由 PIN 派生的 AES key
        """
        payload = json.dumps(credential, ensure_ascii=False)
        enc_path = self._vault_dir / f"{system}{ENC_EXT}"
        _encrypt_and_write(derived_key, payload.encode("utf-8"), enc_path)

    def load_credential(self, system: str, derived_key: bytes) -> dict:
        """解密 <system>.enc 返回凭证字典。

        Returns:
            结构化凭证 dict（含 auth_type + 对应字段）

        Raises:
            NotBoundError: 该系统未绑定
        """
        enc_path = self._vault_dir / f"{system}{ENC_EXT}"
        if not enc_path.exists():
            raise NotBoundError(f"系统 '{system}' 未绑定（{enc_path} 不存在）")
        plaintext = _decrypt_file(derived_key, enc_path)
        return json.loads(plaintext.decode("utf-8"))

    def revoke_token(self, system: str) -> bool:
        """删除 <system>.enc 文件。

        Returns:
            True 如果删除成功，False 如果文件不存在
        """
        enc_path = self._vault_dir / f"{system}{ENC_EXT}"
        if not enc_path.exists():
            return False
        enc_path.unlink()
        return True

    def list_bound_systems(self) -> list[str]:
        """扫描目录列出已绑定的系统名（不涉及解密）。"""
        if not self._vault_dir.exists():
            return []
        try:
            from .constants import AUDIT_STEM
        except ImportError:
            from constants import AUDIT_STEM  # type: ignore[no-redef]
        reserved_stems = {AUDIT_STEM}
        result = []
        for child in sorted(self._vault_dir.iterdir()):
            name = child.name
            # 只匹配 <system>.enc，排除 <provider>.session.enc（v0.2 SSO session 文件）
            if (
                name.endswith(ENC_EXT)
                and not name.endswith(SESSION_ENC_SUFFIX)
                and not name.startswith(".")
            ):
                system = name[:-len(ENC_EXT)]
                if system in reserved_stems:
                    continue
                result.append(system)
        return result

    # -------- v0.2.0: SSO Session 加密存取 --------

    def store_session(
        self, provider: str, session_data: dict, derived_key: bytes
    ) -> None:
        """加密存储 SSO session 数据到 <provider>.session.enc 文件。

        Args:
            provider: SSO provider 名（如 ``quectel_sso``）
            session_data: session json（含 cookies、expires_at、created_at 等）
            derived_key: 由 PIN 派生的 AES key
        """
        payload = json.dumps(session_data, ensure_ascii=False)
        enc_path = self._vault_dir / f"{provider}{SESSION_ENC_SUFFIX}"
        _encrypt_and_write(derived_key, payload.encode("utf-8"), enc_path)

    def load_session(self, provider: str, derived_key: bytes) -> dict:
        """解密 <provider>.session.enc 返回 session 字典。

        Returns:
            session json dict

        Raises:
            NotBoundError: 该 provider 尚未 sso-login
        """
        enc_path = self._vault_dir / f"{provider}{SESSION_ENC_SUFFIX}"
        if not enc_path.exists():
            raise NotBoundError(
                f"provider '{provider}' 未 sso-login（{enc_path.name} 不存在）"
            )
        plaintext = _decrypt_file(derived_key, enc_path)
        return json.loads(plaintext.decode("utf-8"))

    def revoke_session(self, provider: str) -> bool:
        """删除 <provider>.session.enc 文件（即 sso-logout）。

        Returns:
            True 删除成功；False 文件不存在
        """
        enc_path = self._vault_dir / f"{provider}{SESSION_ENC_SUFFIX}"
        if not enc_path.exists():
            return False
        enc_path.unlink()
        return True

    def has_session(self, provider: str) -> bool:
        """判断 provider 是否已有 session 文件（不解密）。"""
        return (self._vault_dir / f"{provider}{SESSION_ENC_SUFFIX}").exists()

    def list_sso_providers(self) -> list[str]:
        """扫描目录列出已有 session 的 provider 名（不涉及解密）。"""
        if not self._vault_dir.exists():
            return []
        result = []
        for child in sorted(self._vault_dir.iterdir()):
            name = child.name
            if name.endswith(SESSION_ENC_SUFFIX) and not name.startswith("."):
                result.append(name[: -len(SESSION_ENC_SUFFIX)])
        return result


# ============================================================================
# SessionKeyCache —— 内存 TTL 缓存
# ============================================================================

class SessionKeyCache:
    """内存 TTL 缓存 —— 只跟 user_id 关联，进程重启后全部失效。

    特性：
    - 30min 滑动过期（每次 get 刷新 last_used）
    - 后台清理任务（每 60s 扫描过期 entry 并覆写清零）
    - lock() 时主动覆写清零
    """

    def __init__(self):
        self._store: dict[str, dict] = {}   # user_id -> {key, expires_at, last_used}
        self._lock = threading.Lock()
        self._start_cleanup_task()

    def unlock(self, user_id: str, derived_key: bytes) -> None:
        """存入派生密钥，设置 30min TTL。"""
        now = time.time()
        with self._lock:
            self._store[user_id] = {
                "key": derived_key,
                "expires_at": now + SESSION_TTL_SECONDS,
                "last_used": now,
            }
        logger.info("user_id=%s vault 已解锁（TTL=%ds）", user_id, SESSION_TTL_SECONDS)

    def get(self, user_id: str) -> Optional[bytes]:
        """取派生密钥。

        不存在或已过期返回 None；命中时刷新 last_used（滑动过期）。
        """
        with self._lock:
            entry = self._store.get(user_id)
            if entry is None:
                return None

            now = time.time()
            if now >= entry["expires_at"]:
                _zero_bytes(entry["key"])
                del self._store[user_id]
                return None

            entry["last_used"] = now
            # 刷新 TTL（滑动过期）
            entry["expires_at"] = now + SESSION_TTL_SECONDS
            return entry["key"]

    def is_unlocked(self, user_id: str) -> bool:
        """检查 user_id 是否已解锁（且未过期）。"""
        return self.get(user_id) is not None

    def get_ttl_remaining(self, user_id: str) -> Optional[int]:
        """返回剩余 TTL 秒数；不存在或已过期返回 None。"""
        with self._lock:
            entry = self._store.get(user_id)
            if entry is None:
                return None
            remaining = int(entry["expires_at"] - time.time())
            if remaining <= 0:
                _zero_bytes(entry["key"])
                del self._store[user_id]
                return None
            return remaining

    def lock(self, user_id: str) -> None:
        """立即清除指定用户的缓存 key（覆写清零后删除）。"""
        with self._lock:
            entry = self._store.pop(user_id, None)
            if entry is not None:
                _zero_bytes(entry["key"])
        logger.info("user_id=%s vault 已锁定", user_id)

    def _cleanup_expired(self) -> None:
        """扫描过期 entry，覆写清零后删除。"""
        now = time.time()
        with self._lock:
            expired = [
                uid for uid, e in self._store.items()
                if now >= e["expires_at"]
            ]
            for uid in expired:
                entry = self._store.pop(uid)
                _zero_bytes(entry["key"])
        if expired:
            logger.debug("清理了 %d 个过期的 session key", len(expired))

    def _cleanup_loop(self) -> None:
        """后台清理循环（在 daemon 线程中运行）。"""
        while True:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                self._cleanup_expired()
            except Exception:
                logger.debug("后台清理任务异常", exc_info=True)

    def _start_cleanup_task(self) -> None:
        """启动后台清理 daemon 线程。"""
        t = threading.Thread(target=self._cleanup_loop, daemon=True, name="vault-cleanup")
        t.start()


# ============================================================================
# 内部工具函数
# ============================================================================

def _derive_key(pin: str, salt: bytes) -> bytearray:
    """用 Argon2id 从 PIN + salt 派生 32 字节 AES 密钥（返回 bytearray 以支持原地清零）。"""
    raw = argon2.low_level.hash_secret_raw(
        secret=pin.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=argon2.low_level.Type.ID,
    )
    return bytearray(raw)


def _encrypt_and_write(key: bytes, plaintext: bytes, path: Path) -> None:
    """AES-256-GCM 加密并写入文件。

    文件格式：nonce(12B) || ciphertext_with_tag
    """
    nonce = os.urandom(AES_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    _write_file(path, nonce + ciphertext)


def _decrypt_file(key: bytes, path: Path) -> bytes:
    """读取并解密 AES-256-GCM 文件。

    Returns:
        解密后的明文字节
    """
    data = _read_file(path)
    nonce = data[:AES_NONCE_LEN]
    ciphertext = data[AES_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _read_file(path: Path) -> bytes:
    """读取文件全部内容。"""
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")
    return path.read_bytes()


def _write_file(path: Path, data: bytes) -> None:
    """写入文件并设置权限 0o600。"""
    path.write_bytes(data)
    os.chmod(path, 0o600)


def _zero_bytes(buf: bytearray) -> None:
    """将 bytearray 内容原地覆写为零。

    要求 buf 为 bytearray（可变），bytes 不可变无法原地清零。
    """
    if not isinstance(buf, bytearray):
        return
    buf[:] = b"\x00" * len(buf)


def _validate_pin_strength(pin: str) -> None:
    """校验 PIN 强度。

    规则:
      - 长度 ≥ PIN_MIN_LENGTH (8)
      - 不允许空白字符（空格、tab、换行等）
      - 必须同时包含：小写字母、大写字母、数字、符号（4 类全要）

    Raises:
        WeakPinError: 不满足要求
    """
    if len(pin) < PIN_MIN_LENGTH:
        raise WeakPinError(f"PIN 长度至少 {PIN_MIN_LENGTH} 位，当前只有 {len(pin)} 位")

    if re.search(r"\s", pin):
        raise WeakPinError("PIN 不能包含空白字符（空格/tab/换行等）")

    has_lower = bool(re.search(r"[a-z]", pin))
    has_upper = bool(re.search(r"[A-Z]", pin))
    has_digit = bool(re.search(r"[0-9]", pin))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pin))

    missing = []
    if not has_lower:
        missing.append("小写字母")
    if not has_upper:
        missing.append("大写字母")
    if not has_digit:
        missing.append("数字")
    if not has_symbol:
        missing.append("符号")

    if missing:
        raise WeakPinError(
            f"PIN 必须同时包含：小写字母、大写字母、数字、符号。缺少：{', '.join(missing)}"
        )
