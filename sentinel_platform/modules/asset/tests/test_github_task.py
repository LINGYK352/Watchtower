"""github_task 叶子单测 —— 任务 CRUD/运行态守卫/级联删结果/无硬限制，注入内存 repo。

覆盖：①add(waiting+关键字必填)②list 分页信封 ③delete 运行中不可删 + 级联删 github_result
④stop 置 stop ⑤list_results 按 github_task_id 过滤 ⑥size 无硬上限。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.asset import github_task as gt


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q):
        for d in self.docs:
            if all(str(d.get(k)) == str(v) for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def count_documents(self, q):
        return len(self._filter(q))
    def _filter(self, q):
        import re
        out = []
        for d in self.docs:
            ok = True
            for k, v in q.items():
                if isinstance(v, dict) and "$regex" in v:
                    if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                        ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out
    def find(self, q):
        self._r = self._filter(q); return self
    def sort(self, *a):
        return self
    def skip(self, n):
        self._r = self._r[n:]; return self
    def limit(self, n):
        self._r = self._r[:n]; return self
    def __iter__(self):
        return iter(self._r)
    def insert_one(self, doc):
        doc["_id"] = "g%d" % (len(self.docs) + 1); self.docs.append(doc)
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            class _R: modified_count = 1
            return _R()
        class _R0: modified_count = 0
        return _R0()
    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
            class _R: deleted_count = 1
            return _R()
        class _R0: deleted_count = 0
        return _R0()
    def delete_many(self, q):
        keep, n = [], 0
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                n += 1
            else:
                keep.append(d)
        self.docs = keep
        class _R: deleted_count = n
        return _R()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class TestGithubTask(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())

    def tearDown(self):
        set_repo(None)

    def test_add_and_list(self):
        r = gt.add_task("找密钥", "AKIA")
        self.assertNotIn("error", r)
        self.assertEqual(r["status"], "waiting")
        lst = gt.list_tasks({})
        self.assertEqual(lst["total"], 1)
        self.assertEqual(set(lst), {"page", "size", "total", "items"})

    def test_add_empty_keyword(self):
        self.assertIn("error", gt.add_task("x", ""))

    def test_add_name_defaults_to_keyword(self):
        r = gt.add_task("", "password")
        self.assertEqual(r["name"], "password")

    def test_delete_done_task_cascades_results(self):
        gt.add_task("t", "kw")
        from sentinel_platform.core import get_repo
        tid = gt.list_tasks({})["items"][0]["_id"]
        # 置 done 才可删
        get_repo().collection("github_task").update_one({"_id": tid}, {"$set": {"status": "done"}})
        get_repo().collection("github_result").insert_one({"github_task_id": tid, "url": "x"})
        r = gt.delete_tasks([tid])
        self.assertEqual(r["deleted"], 1)
        self.assertEqual(r["results_deleted"], 1)

    def test_delete_running_task_rejected(self):
        gt.add_task("t", "kw")   # status=waiting（非可删态）
        tid = gt.list_tasks({})["items"][0]["_id"]
        from sentinel_platform.core import get_repo
        get_repo().collection("github_task").update_one({"_id": tid}, {"$set": {"status": "running"}})
        self.assertIn("error", gt.delete_tasks([tid]))

    def test_stop(self):
        gt.add_task("t", "kw")
        tid = gt.list_tasks({})["items"][0]["_id"]
        self.assertEqual(gt.stop_tasks([tid])["modified"], 1)
        self.assertEqual(gt.list_tasks({})["items"][0]["status"], "stop")

    def test_delete_empty(self):
        self.assertIn("error", gt.delete_tasks([]))

    def test_list_results_filter(self):
        from sentinel_platform.core import get_repo
        get_repo().collection("github_result").insert_one({"github_task_id": "t1", "url": "a"})
        get_repo().collection("github_result").insert_one({"github_task_id": "t2", "url": "b"})
        self.assertEqual(gt.list_results({"github_task_id": "t1"})["total"], 1)

    def test_list_no_hard_cap(self):
        self.assertEqual(gt.list_tasks({"size": 99999})["size"], 99999)


if __name__ == "__main__":
    unittest.main()
