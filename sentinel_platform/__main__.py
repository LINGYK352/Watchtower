"""本地开发启动入口 —— `python -m sentinel_platform`。

用 Flask 内置服务器起（仅开发/冒烟；生产用 gunicorn sentinel_platform.wsgi:application）。
端口默认 5003，可环境变量 SENTINEL_PORT / SENTINEL_HOST 覆盖。

    python -m sentinel_platform            # 起在 127.0.0.1:5003
    SENTINEL_PORT=8080 python -m sentinel_platform
"""
from __future__ import annotations

import os

from sentinel_platform.bootstrap import create_app


def main() -> None:
    host = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("SENTINEL_PORT", "5003") or 5003)
    except ValueError:
        port = 5003
    app = create_app()
    # debug 关（避免 reloader 二次 import 装配）；生产请用 gunicorn
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
