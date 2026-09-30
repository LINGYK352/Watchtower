"""负优化回归 harness 统一入口。

跑法：python -m sentinel_platform.tests.regression
只 discover 本目录 test_reg_*.py（确定性回归层）；live_fire/ 的 test_live_fire.py 不在此 pattern，
空 scenarios 时它整类 skip，不误报绿。退出码 0=全绿 / 非0=有失败，供门禁使用。
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
# top_level_dir = 含 sentinel_platform/ 的仓库根（现有测试全用绝对导入 sentinel_platform.xxx）
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_HERE))))


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=_HERE, pattern="test_reg_*.py", top_level_dir=_REPO_ROOT)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
