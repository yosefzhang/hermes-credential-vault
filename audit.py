"""加密审计日志 —— 每条事件用 derived_key 加密后追加存储。

事件格式（加密前）：
    {"ts": "2026-07-08T16:30:00Z", "event": "unlock", "details": "..."}

每条独立加密后追加：nonce(12B) || ciphertext || \\n
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from .vault_core import _read_file, _write_file
    from .constants import AES_NONCE_LEN
except ImportError:
    from vault_core import _read_file, _write_file  # type: ignore[no-redef]
    from constants import AES_NONCE_LEN  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


EVENT_TYPES = (
    "initialize",
    "unlock",
    "lock",
    "bad_pin",
    "bind",
    "revoke",
    "api_call",
    "list",
)

_RECORD_DELIMITER = b"\n"


class AuditLog:
    """加密审计日志，记录 vault 操作事件。

    每条记录独立加密后追加到文件末尾，格式：
        nonce(12B) || ciphertext || \\n
    """

    def __init__(self, audit_file: Path):
        self._audit_file = audit_file

    def append(
        self, user_id: str, event_type: str, details: str, derived_key: bytes
    ) -> None:
        """追加一条加密审计记录。"""
        record = json.dumps(
            {
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event": event_type,
                "details": details,
            },
            ensure_ascii=False,
        )

        self._audit_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        encrypted = _encrypt_record(derived_key, record.encode("utf-8"))
        entry = encrypted + _RECORD_DELIMITER

        if self._audit_file.exists():
            existing = _read_file(self._audit_file)
            _write_file(self._audit_file, existing + entry)
        else:
            _write_file(self._audit_file, entry)

    def read_all(self, derived_key: bytes) -> list[dict]:
        """解密并返回全部审计条目。解密失败的条目静默跳过。"""
        if not self._audit_file.exists():
            return []

        raw_data = _read_file(self._audit_file)
        if not raw_data:
            return []

        results = []
        for chunk in raw_data.split(_RECORD_DELIMITER):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                plaintext = _decrypt_record(derived_key, chunk)
                results.append(json.loads(plaintext.decode("utf-8")))
            except Exception:
                continue

        return results


def _encrypt_record(key: bytes, plaintext: bytes) -> bytes:
    """加密单条记录：nonce(12B) || ciphertext。"""
    nonce = os.urandom(AES_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def _decrypt_record(key: bytes, data: bytes) -> bytes:
    """解密单条记录。"""
    nonce = data[:AES_NONCE_LEN]
    ciphertext = data[AES_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
