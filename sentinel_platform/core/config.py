"""平台配置加载。

独立于 app.config，只读平台需要的键。与旧内核共用同一份 config.yaml（同 Mongo 实例/DB），
从而平台读写相同集合。惰性、只读、缺省安全（键缺失回退默认，不因配置不全崩）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# _ROOT = sentinel_platform 目录；_PROJECT_ROOT = 项目根（sentinel_platform 与 config/ 同级）
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PROJECT_ROOT = os.path.dirname(_ROOT) if os.path.basename(_ROOT) == "sentinel_platform" else _ROOT

def _config_candidates() -> List[str]:
    """候选配置路径（每次调用重算，勿在模块级冻结）。

    候选顺序：显式环境变量 > 新根 config/（真配置 > 样例）> docker/config/（Docker 部署挂卷）
    > 旧 app/（迁移期兜底）。
    **环境变量必须运行时读**：早期版本把本列表冻结为模块级常量，`SENTINEL_PLATFORM_CONFIG`
    在 config.py 首次 import 时求值——若有模块先 import config 再设该 env（如测试包 __init__），
    env override 会静默失效。改为函数内每次求值，import 顺序无关。
    """
    return [
        os.environ.get("SENTINEL_PLATFORM_CONFIG", ""),
        os.path.join(_PROJECT_ROOT, "config", "config.yaml"),
        os.path.join(os.getcwd(), "config", "config.yaml"),
        os.path.join(_PROJECT_ROOT, "docker", "config", "config.yaml"),
        os.path.join(_PROJECT_ROOT, "config", "config.yaml.example"),
        os.path.join(_ROOT, "app", "config.yaml"),
        os.path.join(_ROOT, "app", "config.yaml.example"),
    ]


# 兼容旧引用（部分测试/代码读常量）；实际加载走 _config_candidates() 运行时求值。
_CONFIG_CANDIDATES = _config_candidates()


@dataclass
class PlatformConfig:
    mongo_uri: str = "mongodb://127.0.0.1:27017/"
    mongo_db: str = "sentinel"
    auth: bool = True
    api_key: str = ""
    # 其余平台键按需扩展（FOFA/HUNTER/FEISHU 等由各模块从 raw 读，见 raw 属性）
    raw: Dict[str, Any] = field(default_factory=dict)

    def section(self, *keys: str, default: Any = None) -> Any:
        """读原始配置任意嵌套键，供各模块取自己的配置段（如 FOFA/HUNTER）。"""
        cur: Any = self.raw
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur if cur is not None else default


def _dig(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur if cur is not None else default


def load_config(path: Optional[str] = None) -> PlatformConfig:
    cfg = PlatformConfig()
    cfg_path = path or _first_existing(_config_candidates())
    if not cfg_path:
        return cfg
    try:
        import yaml
        with open(cfg_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except Exception:
        return cfg
    if not isinstance(raw, dict):
        return cfg
    cfg.raw = raw
    cfg.mongo_uri = _dig(raw, "MONGO", "URI", default=cfg.mongo_uri)
    cfg.mongo_db = _dig(raw, "MONGO", "DB", default=cfg.mongo_db)
    # 兼容 ARL/SENTINEL 两种配置段名（迁移期）
    auth_sec = raw.get("SENTINEL") or raw.get("ARL") or {}
    if isinstance(auth_sec, dict):
        cfg.auth = bool(auth_sec.get("AUTH", cfg.auth))
        cfg.api_key = auth_sec.get("API_KEY", cfg.api_key) or ""
    return cfg


def _first_existing(cands: List[str]) -> Optional[str]:
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None


_cached: Optional[PlatformConfig] = None


def get_config() -> PlatformConfig:
    global _cached
    if _cached is None:
        _cached = load_config()
    return _cached


def reset_config_cache() -> None:
    global _cached
    _cached = None
