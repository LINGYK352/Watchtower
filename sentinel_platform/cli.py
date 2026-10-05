"""瞭望塔 CLI —— 终端直接操作渗透会话。

用法:
    python -m sentinel_platform.cli resume <session_id>    续跑/重跑指定会话
    python -m sentinel_platform.cli run <session_id>       等同 resume
    python -m sentinel_platform.cli status <session_id>    查会话状态
    python -m sentinel_platform.cli list                   列出最近会话

在 Docker 容器内执行:
    docker exec docker-worker-1 python -m sentinel_platform.cli resume <session_id>
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _init():
    from sentinel_platform.bootstrap import register_all
    register_all()


def cmd_resume(session_id: str):
    """续跑会话（从 checkpoint 接续，不清历史）。"""
    _init()
    from sentinel_platform.core import get_repo
    from sentinel_platform.contracts import Collections
    coll = get_repo().collection(Collections.PENTEST_SESSION)

    # 查会话
    from bson import ObjectId
    try:
        doc = coll.find_one({"_id": ObjectId(session_id)})
    except Exception:
        doc = coll.find_one({"_id": session_id})
    if not doc:
        print(f"会话不存在: {session_id}")
        sys.exit(1)

    status = doc.get("status", "")
    print(f"会话: {session_id}")
    print(f"目标: {doc.get('site', '')}")
    print(f"状态: {status}")
    print(f"轮次: {doc.get('round', 0)}")
    print(f"Token: {doc.get('total_tokens', 0)}")

    if status == "running":
        print("会话正在运行中，无需恢复。")
        return

    # 改状态为 waiting 让 scheduler 捡起来
    coll.update_one({"_id": doc["_id"]}, {"$set": {"status": "waiting"}})
    print(f"\n已将状态改为 waiting，scheduler 将自动投递执行。")
    print(f"恢复命令: python -m sentinel_platform.cli resume {session_id}")


def cmd_status(session_id: str):
    """查看会话状态。"""
    _init()
    from sentinel_platform.core import get_repo
    from sentinel_platform.contracts import Collections
    coll = get_repo().collection(Collections.PENTEST_SESSION)
    from bson import ObjectId
    try:
        doc = coll.find_one({"_id": ObjectId(session_id)})
    except Exception:
        doc = coll.find_one({"_id": session_id})
    if not doc:
        print(f"会话不存在: {session_id}")
        sys.exit(1)
    print(f"ID:     {doc.get('_id')}")
    print(f"目标:   {doc.get('site', '')}")
    print(f"模式:   {doc.get('mode', '')}")
    print(f"状态:   {doc.get('status', '')}")
    print(f"轮次:   {doc.get('round', 0)}")
    print(f"Token:  {doc.get('total_tokens', 0)}")
    print(f"模型:   {doc.get('model', '')}")
    print(f"更新:   {doc.get('update_date', '')}")
    if doc.get("last_error"):
        print(f"错误:   {doc.get('last_error')}")


def cmd_list():
    """列出最近 10 个会话。"""
    _init()
    from sentinel_platform.core import get_repo
    from sentinel_platform.contracts import Collections
    coll = get_repo().collection(Collections.PENTEST_SESSION)
    print(f"{'ID':<26} {'状态':<12} {'轮次':<6} {'Token':<10} {'目标'}")
    print("-" * 90)
    for doc in coll.find().sort("_id", -1).limit(10):
        print(f"{str(doc.get('_id','')):<26} {doc.get('status',''):<12} {doc.get('round',0):<6} {doc.get('total_tokens',0):<10} {doc.get('site','')[:30]}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd in ("resume", "run"):
        if len(sys.argv) < 3:
            print("用法: python -m sentinel_platform.cli resume <session_id>")
            sys.exit(1)
        cmd_resume(sys.argv[2])
    elif cmd == "status":
        if len(sys.argv) < 3:
            print("用法: python -m sentinel_platform.cli status <session_id>")
            sys.exit(1)
        cmd_status(sys.argv[2])
    elif cmd == "list":
        cmd_list()
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
