"""平台日志。独立于 app.utils.get_logger，纯标准库 logging。"""
from __future__ import annotations

import logging

_LOGGER_NAME = "sentinel_platform"
_configured = False


def get_logger() -> logging.Logger:
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if not _configured:
        if not logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            logger.addHandler(h)
        logger.setLevel(logging.INFO)
        _configured = True
    return logger
