"""risk_intel 类别装配 —— 把本类别各叶子实现注册进 registry。

bootstrap 启动时调本模块 register(registry)。当前已就绪叶子：vuln_intel(VULN_INTEL)、vuln_center(FINDING)。
其余叶子（asset_intel）实现后在此追加注册（INTEL）。
"""
from __future__ import annotations

from sentinel_platform.contracts import ROLE


def register(registry) -> None:
    # vuln_intel：漏洞情报查询（ROLE.VULN_INTEL）
    from .vuln_intel import get_service as _vuln_intel_service
    registry.register(ROLE.VULN_INTEL, _vuln_intel_service())

    # vuln_center：漏洞中心/发现登记（ROLE.FINDING）
    from .vuln_center import get_service as _finding_service
    registry.register(ROLE.FINDING, _finding_service())

    # asset_intel：资产情报归集（ROLE.INTEL）
    from .asset_intel import get_service as _intel_service
    registry.register(ROLE.INTEL, _intel_service())

    # attack_chain：攻击链情报（无 ROLE，字符串键 "attack_chain_service"）
    from .attack_chain import get_service as _attack_chain_service
    registry.register("attack_chain_service", _attack_chain_service())

    # scan_result：扫描结果集合查询/删除（无 ROLE，字符串键 "scan_result_service"）
    from .scan_result import get_service as _scan_result_service
    registry.register("scan_result_service", _scan_result_service())

    # poc：灯塔 PoC 扫描结果（无 ROLE，字符串键 "poc_service"）。
    # 叶子是模块级函数集合，注册模块对象作门面（router 经 registry 取，不再直连 import 叶子）。
    from . import poc as _poc
    registry.register("poc_service", _poc)

    # unit_view：单位视图/反查（无 ROLE，字符串键 "unit_view_service"）
    from . import unit_view as _unit_view
    registry.register("unit_view_service", _unit_view)
