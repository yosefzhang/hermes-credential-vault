"""让 tests 目录下的测试文件能 import 上一级的插件模块。"""
import sys
from pathlib import Path

# 把插件根目录加入 sys.path，让 tests 能 `from vault_core import ...`
_plugin_root = Path(__file__).parent.parent
sys.path.insert(0, str(_plugin_root))
