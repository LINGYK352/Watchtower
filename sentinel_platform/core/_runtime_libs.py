"""core/_runtime_libs —— 运行时依赖库热更通道（v1.21.159 新建，可复用基建）。

**为什么存在**：热更新只能推**文件**（走 TRACK_DIRS 分发），推不动 `pip install` 的依赖。
但存量用户的镜像基板可能缺某些后加的依赖（如报告模板的 docxtpl/matplotlib——157-36 才进
requirements，而分发镜像基板停在更早版本，`pip install` 装不到存量实例）。

**机制**：把所需依赖**解压成包目录**（非 .whl，可直接 import）放进项目根 `runtime_libs/`，
该目录进 TRACK_DIRS 随热更分发到存量实例；本模块在最早 import 时把它 **append 到 sys.path 末尾**
（末尾＝优先用镜像已装的同名包，runtime_libs 仅补镜像缺失的——绝不覆盖镜像里已就绪的版本）。
于是存量用户热更后即获得新依赖，**无需重装、无需 rebuild 镜像**。

**平台约束**：解压的 wheel 必须是目标运行平台（生产/VM = Linux x86_64 cp38）的：
纯 Python 包（py3-none-any）任意平台解压即用；编译型包（cp38 manylinux，含 .so）因目标同架构
Linux 解压即用（.so 是 Linux ELF，与解压所在开发机无关）。放 wheel 时只取目标平台版本，
剔除 win_amd64/其他 py 版本的误入项。

**以后依赖更新复用此法**：`unzip <目标平台wheel> -d runtime_libs/` → 随热更分发即到达存量用户。
只依赖 stdlib。被 core/__init__.py 顶部 import → 全进程（web/worker/scheduler/cli）自动生效。
"""
from __future__ import annotations

import os
import sys


def _runtime_libs_dir() -> str:
    """runtime_libs 绝对路径：本文件 core/_runtime_libs.py → core → sentinel_platform → <项目根>/runtime_libs。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "runtime_libs")


def install() -> bool:
    """把 runtime_libs/ append 到 sys.path 末尾（存在且未加过才加）。返回是否生效。
    末尾追加＝镜像已装的同名包优先解析，runtime_libs 仅补镜像缺失项（不覆盖镜像就绪版本）。
    幂等：多次调用/多进程各自 import 只加一次。异常吞掉（依赖热更是补强，失败不阻断启动）。"""
    try:
        d = _runtime_libs_dir()
        if os.path.isdir(d) and d not in sys.path:
            sys.path.append(d)          # 末尾：镜像已装优先，此处仅兜底补缺
            return True
    except Exception:
        pass
    return False


# import 即安装（core 被全平台普遍 import → 各进程入口自动生效，无需各入口显式调）
install()
