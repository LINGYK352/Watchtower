"""侦察工具对接集 —— 一工具一对接（防腐层）。

每个对接：调用 external 工具 + 解析原始输出 + 结构化成 models 记录。
新增工具 = 加一个对接文件 + 在此导出 + 在 registry 注册角色，其余零改动。
"""
from .nuclei import Nuclei
from .httpx import Httpx
from .naabu import Naabu
from .weakbrute import WeakBrute
from .dnsx import Dnsx
from .subfinder import Subfinder
from .nmap_service import NmapService
from .massdns import Massdns
from .katana import Katana
from .npoc import Npoc

__all__ = ["Nuclei", "Httpx", "Naabu", "WeakBrute", "Dnsx", "Subfinder", "NmapService", "Massdns", "Katana", "Npoc"]
