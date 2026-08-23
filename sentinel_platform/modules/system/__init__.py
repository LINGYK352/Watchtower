"""system —— 系统设置类别（对应前端「系统设置」菜单组）。

叶子：proxy（代理中心）/ user_manage（用户管理）/ api_keys（API 密钥）/
     log_monitor（日志监测）/ access_log（访问日志）/ guard_log（拦截日志）。

叶子只提供 registry 能力，不放 HTTP 路由（路由集中在 sentinel_platform/router/）。
"""
