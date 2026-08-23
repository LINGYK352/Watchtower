"""github 执行闭环单测 —— 补净室迁移丢失的执行层（run_waiting/run_one/run_due）。

覆盖：①run_one 认领 waiting→搜索→存结果→done + result_count ②无 token 标 error 不静默返0
③协作式取消(stop 中途停) ④幂等(同 hash 不重存) ⑤run_waiting 扫全部 waiting
⑥monitor run_due 只跑到期的 + 跨轮去重 + 推进 next_run。内存 repo 替身 + monkeypatch 客户端。
"""
import unittest

from sentinel_platform.core import set_repo, get_repo
from sentinel_platform.modules.asset import github_task as gt
from sentinel_platform.modules.asset import github_monitor as gm
from sentinel_platform.modules.asset import _github_client as ghc


class _Coll:
    """支持投影(第2 arg)的内存集合替身，贴近 pymongo。"""
    def __init__(self):
        self.docs = []
        self._n = 0
    def _match(self, d, q):
        for k, v in q.items():
            if isinstance(v, dict):
                continue
            if d.get(k) != v:
                return False
        return True
    def find_one(self, q, proj=None):
        for d in self.docs:
            if self._match(d, q):
                return d
        return None
    def find(self, q, proj=None):
        return [d for d in self.docs if self._match(d, q)]
    def count_documents(self, q):
        return len([d for d in self.docs if self._match(d, q)])
    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "d%d" % self._n)
        self.docs.append(doc)
        class _R: pass
        r = _R(); r.inserted_id = doc["_id"]; return r
    def update_one(self, q, upd):
        d = self.find_one(q)
        class _R: modified_count = 0
        r = _R()
        if d:
            d.update(upd.get("$set", {}))
            for k, inc in (upd.get("$inc") or {}).items():
                d[k] = (d.get(k, 0) or 0) + inc
            r.modified_count = 1
        return r


class _Repo:
    def __init__(self):
        self._c = {}
    def collection(self, name):
        return self._c.setdefault(name, _Coll())


class TestGithubTaskExec(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self._orig_has = ghc.has_token
        self._orig_search = ghc.search

    def tearDown(self):
        ghc.has_token = self._orig_has
        ghc.search = self._orig_search
        set_repo(None)

    def _seed_task(self, keyword="AKIA", status="waiting"):
        get_repo().collection("github_task").insert_one(
            {"_id": "t1", "name": keyword, "keyword": keyword, "status": status})
        return "t1"

    def test_run_one_success(self):
        ghc.has_token = lambda: True
        ghc.search = lambda kw, cancel_check=None: [
            {"repo": "a/b", "path": "c.py", "hash_md5": "h1", "html_url": "u1"},
            {"repo": "a/b", "path": "d.py", "hash_md5": "h2", "html_url": "u2"}]
        tid = self._seed_task()
        r = gt.run_one(tid)
        self.assertEqual(r["status"], "done")
        self.assertEqual(r["result_count"], 2)
        task = get_repo().collection("github_task").find_one({"_id": tid})
        self.assertEqual(task["status"], "done")
        self.assertEqual(get_repo().collection("github_result").count_documents({}), 2)

    def test_run_one_no_token_errors_not_silent(self):
        ghc.has_token = lambda: False
        tid = self._seed_task()
        r = gt.run_one(tid)
        self.assertEqual(r["error"], "no_token")
        self.assertEqual(get_repo().collection("github_task").find_one({"_id": tid})["status"], "error")

    def test_run_one_idempotent_dedup(self):
        ghc.has_token = lambda: True
        hits = [{"repo": "a/b", "path": "c.py", "hash_md5": "h1", "html_url": "u1"}]
        ghc.search = lambda kw, cancel_check=None: hits
        tid = self._seed_task()
        gt.run_one(tid)
        # 重置为 waiting 再跑一次，同 hash 不重复入库
        get_repo().collection("github_task").update_one({"_id": tid}, {"$set": {"status": "waiting"}})
        gt.run_one(tid)
        self.assertEqual(get_repo().collection("github_result").count_documents({}), 1)

    def test_run_one_cooperative_stop(self):
        ghc.has_token = lambda: True
        # 搜索时把任务置 stop → run_one 检测到 stopped 不写 done
        def _search(kw, cancel_check=None):
            get_repo().collection("github_task").update_one({"_id": "t1"}, {"$set": {"status": "stop"}})
            return [{"repo": "a/b", "path": "c.py", "hash_md5": "h1"}]
        ghc.search = _search
        tid = self._seed_task()
        r = gt.run_one(tid)
        self.assertTrue(r.get("stopped"))

    def test_run_waiting_scans_all(self):
        ghc.has_token = lambda: True
        ghc.search = lambda kw, cancel_check=None: []
        get_repo().collection("github_task").insert_one({"_id": "t1", "keyword": "a", "status": "waiting"})
        get_repo().collection("github_task").insert_one({"_id": "t2", "keyword": "b", "status": "waiting"})
        r = gt.run_waiting()
        self.assertEqual(r["picked"], 2)
        self.assertEqual(r["done"], 2)


class TestGithubMonitorExec(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self._orig_has = ghc.has_token
        self._orig_search = ghc.search
        ghc.has_token = lambda: True

    def tearDown(self):
        ghc.has_token = self._orig_has
        ghc.search = self._orig_search
        set_repo(None)

    def test_run_due_only_due_and_dedup(self):
        ghc.search = lambda kw, cancel_check=None: [
            {"repo": "a/b", "path": "c.py", "hash_md5": "h1"}]
        # 到期任务（next_run_date 过去）
        get_repo().collection("github_scheduler").insert_one(
            {"_id": "m1", "keyword": "k", "cron": "* * * * *", "status": "running",
             "next_run_date": "2000-01-01 00:00:00", "run_number": 0})
        # 未到期任务（未来）
        get_repo().collection("github_scheduler").insert_one(
            {"_id": "m2", "keyword": "k2", "cron": "* * * * *", "status": "running",
             "next_run_date": "2099-01-01 00:00:00", "run_number": 0})
        r = gm.run_due()
        self.assertEqual(r["picked"], 1)   # 只跑到期的 m1
        self.assertEqual(get_repo().collection("github_monitor_result").count_documents({}), 1)
        # run_number 递增 + next_run 推进（不再是过去时间）
        m1 = get_repo().collection("github_scheduler").find_one({"_id": "m1"})
        self.assertEqual(m1["run_number"], 1)
        self.assertNotEqual(m1["next_run_date"], "2000-01-01 00:00:00")

    def test_monitor_cross_round_dedup(self):
        ghc.search = lambda kw, cancel_check=None: [{"repo": "a/b", "path": "c.py", "hash_md5": "h1"}]
        get_repo().collection("github_scheduler").insert_one(
            {"_id": "m1", "keyword": "k", "cron": "* * * * *", "status": "running",
             "next_run_date": "2000-01-01 00:00:00", "run_number": 0})
        gm.run_one("m1")
        gm.run_one("m1")   # 第二轮同 hash 不重存
        self.assertEqual(get_repo().collection("github_monitor_result").count_documents({}), 1)


if __name__ == "__main__":
    unittest.main()
