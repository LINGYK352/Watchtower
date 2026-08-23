"""kernel/recon/native —— native 纯 Python 侦察能力（无外部二进制、无第三方库）。

区别于 `recon/tools/`（external 工具 subprocess 对接）：native 能力用标准库从零实现通用技术
（TLS 取证 / 字典探测 / vhost 碰撞 / 截图驱动），恒可用、可离线单测、无需 vendor。
每能力一文件，产出 `recon/models` 的结构化记录，经 registry 注册供 recon pipeline 消费。
"""
