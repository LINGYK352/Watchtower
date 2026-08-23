"""risk_intel —— 漏洞与情报类别（对应前端一级菜单组「漏洞与情报」）。

叶子模块（一菜单叶子=一 .py）：
  vuln_intel  漏洞情报（VULN_INTEL，本次落地；+ 私有 _feed.py 抓取器辅助）
  asset_intel 资产情报（INTEL，未建）· vuln_center 漏洞中心（FINDING，未建）
  poc PoC 信息 · attack_chain 攻击链情报 · unit_view 单位视图（均未建）

叶子只提供 registry 能力，不放路由（路由在 router/）；实现 ROLE 的叶子在 register.py 注册。
"""
