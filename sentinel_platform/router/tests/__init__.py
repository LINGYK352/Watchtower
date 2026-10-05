"""router E2E 测试包初始化。

在任何 router E2E 测试模块被导入前（Python 先执行包 __init__），把平台配置固定到
本目录的 `_test_config.yaml`（AUTH=false），并清空 get_config 缓存。

为什么需要：router E2E 测试测端点逻辑，不测网关鉴权，全部假设 auth_enabled()=False
（历史上因 gateway 只读 AUTH/ARL.AUTH、样例配置里没有 → 恰好 False 才成立）。gateway 修复
为读 SENTINEL.AUTH 后，若测试恰好加载到 SENTINEL.AUTH:true 的样例配置，无 token 的 E2E
会全部 401。用确定性测试配置消除对「环境里恰好存在哪份 config」的隐式依赖。
需要测鉴权的 test_user_auth_e2e 仍自行 mock.patch(auth_enabled=True)，不受影响。
"""
import os as _os

_os.environ.setdefault(
    "SENTINEL_PLATFORM_CONFIG",
    _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "_test_config.yaml"),
)

try:  # 若 get_config 已被先前导入缓存，重置以确保读到测试配置（load_config 现运行时读 env）
    from sentinel_platform.core.config import reset_config_cache as _reset
    _reset()
except Exception:
    pass
