"""负优化回归 harness（R-01 评测地基·确定性回归层）。

把项目反复踩坑的负优化点固化成场景回归用例：给定输入 → 断言预期输出 → 可重复跑。
目的不是替代各模块单测，而是把"血泪事故"锁成红线，改动踩回同一个坑时立刻 FAIL。

统一入口：python -m sentinel_platform.tests.regression
纯确定性层：不联网、不调 LLM、不碰生产库（mock/注入 fake repo）。
实弹效果评测在 live_fire/（待用户填真实授权靶标，空则全 skip）。
"""
