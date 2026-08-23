"""对外 REST 端点集 —— 一类别一文件（endpoints/<类别>.py），继承 core.web.BaseResource。

各 endpoints 经 registry 调叶子能力（缺失降级），响应统一走 router.envelope 信封。
本轮已建：meta（健康/版本，端到端范式）。其余类别端点各 AI 分领（见 MODULE_STATUS 核心路由区块）。
"""
