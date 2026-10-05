"""asset —— 资产中心类别（对应前端一级菜单组「资产中心」）。

叶子模块（一菜单叶子=一 .py）：
  search  资产检索（8 侦察集合查询/去重/删除/导出/站点标签，本次落地）
  groups 资产分组 · monitor 资产监控 · fingerprint 指纹管理 ·
  github_task GitHub 任务 · github_monitor GitHub 监控（均未建）

叶子只提供能力，不放路由（路由在 router/endpoints/asset.py）。多数叶子无 ROLE，
经 registry 字符串键暴露给核心路由（照 api_keys 先例）；register.py 统一注册。
"""
