"""常量集中定义 —— 路径、TTL、加密参数、系统白名单、token 模式等。

所有魔法值集中在一个模块，其他模块只从这里引用。
"""

# ============================================================================
# 加密参数
# ============================================================================

ARGON2_MEMORY_COST = 65536   # 64 MB (KiB)
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
KEY_LEN = 32                 # AES-256
AES_NONCE_LEN = 12           # GCM 标准 nonce 长度
SALT_LEN = 16                # 随机盐长度

# ============================================================================
# TTL（时间相关）
# ============================================================================

SESSION_TTL_SECONDS = 30 * 60        # 30 分钟滑动过期
CLEANUP_INTERVAL_SECONDS = 60        # 后台清理任务频率

# ============================================================================
# PIN 强度
# ============================================================================

PIN_MIN_LENGTH = 8

# ============================================================================
# 支持的认证类型
# ============================================================================

AUTH_TYPE_BASIC = "basic"
AUTH_TYPE_BEARER = "bearer"
AUTH_TYPE_SSO_COOKIE = "sso_cookie"
SUPPORTED_AUTH_TYPES = (AUTH_TYPE_BASIC, AUTH_TYPE_BEARER)  # bind 命令支持的 auth 类型
ALL_AUTH_TYPES = (AUTH_TYPE_BASIC, AUTH_TYPE_BEARER, AUTH_TYPE_SSO_COOKIE)

# 注：系统白名单不再在此定义。
# 系统由 config.yaml → plugins.entries.hermes-credential-vault.systems 动态声明。
# 运行时通过 __init__.py 的 load_systems_config() 读取。

# ============================================================================
# 命令前缀
# ============================================================================

CMD_PREFIX = "/vault"

# ============================================================================
# vault 目录名（相对 profile 根）
# ============================================================================

VAULT_DIRNAME = "vault"

# ============================================================================
# 已知 token 正则模式（用于 transform_tool_result 兜底脱敏）
# ============================================================================

TOKEN_PATTERNS = [
    r"ATATT3xFfGF0[A-Za-z0-9_\-]{20,}",    # Atlassian PAT
    r"glpat-[A-Za-z0-9_\-]{20,}",           # GitLab PAT
    r"ghp_[A-Za-z0-9]{36,}",                # GitHub PAT
    r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",      # 通用 Bearer token
]

# ============================================================================
# vault 文件
# ============================================================================

SALT_FILE = ".salt"
VERIFY_FILE = ".verify"
AUDIT_FILE = "audit.log.enc"

# audit.log.enc 文件占用了通配 *.enc 扫描，需要在系统列表中排除
AUDIT_STEM = "audit.log"

# 文件扩展名
ENC_EXT = ".enc"
SESSION_ENC_SUFFIX = ".session.enc"    # v0.2.0: SSO cookie 集合的存储后缀

# SSO 相关
SSO_LOGIN_TIMEOUT_SECONDS = 30         # Playwright 子进程登录超时
SSO_REFRESH_THRESHOLD_SECONDS = 24 * 3600  # token 剩余 < 24h 时提示用户

# 固定校验字符串（用于 .verify 文件）
VERIFY_PLAINTEXT = b"VAULT_VERIFY_MAGIC_V1"
