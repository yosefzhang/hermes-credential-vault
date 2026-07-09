# Hermes Credential Vault Plugin

Hermes Agent plugin for per-user encrypted credential storage (JIRA/Confluence/PMS tokens).

## Commands

```bash
# Run all tests (must run from tests/ directory)
cd tests && python3 -m pytest -v

# Run single test file
cd tests && python3 -m pytest test_vault_core.py -v

# Run single test
cd tests && python3 -m pytest test_vault_core.py::TestPinManagement::test_verify_pin_success -v
```

## Architecture

- **Plugin entry**: `__init__.py` → `register(ctx)` called by Hermes PluginManager
- **Loaded as**: `hermes_plugins.hermes_credential_vault` (Hermes runtime namespace)
- **Cannot import from repo root**: `__init__.py` uses relative imports that fail outside package context

## Module Import Pattern

All modules use dual-import for test compatibility:
```python
try:
    from .constants import ...  # package mode (Hermes runtime)
except ImportError:
    from constants import ...   # direct import mode (tests)
```

## Test Quirks

- **Must run from `tests/` directory** — running from repo root fails because pytest discovers the parent `__init__.py` which has relative imports
- `tests/conftest.py` adds plugin root to `sys.path` for direct imports
- No pytest config file — async tests use `pytest.mark.asyncio` decorator
- Dependencies: `argon2-cffi`, `cryptography`, `httpx`, `pytest`, `pytest-asyncio`

## Security Constraints

- **Never log PIN/token/derived_key** — even at DEBUG level
- **Sensitive data must be zeroed** after use (`_zero_bytes`, `_zero_str`)
- **File permissions**: all vault files written with `0o600`
- **No hardcoded paths** — use `constants.py` + `get_hermes_home()`

## Known Unverified (TODO)

- `gateway.send_message` API — 4 fallback strategies implemented, needs real-device verification
- `event.source.chat_type` field names for Feishu adapter
- PMS authentication method (currently Bearer Token)
