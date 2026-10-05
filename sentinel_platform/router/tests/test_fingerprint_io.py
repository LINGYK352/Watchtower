"""fingerprint export/upload 端点 e2e —— 真 app + FakeRepo，验证 YAML 导出/导入不孤岛。

链路：前端 fingerprintApi.exportUrl/upload → /api/fingerprint/{export,upload}/ →
endpoint 直调 fingerprint.export_yaml/import_yaml → YAML 文本流 / 导入摘要。
覆盖：export 返 YAML 文件流、upload 逐条校验(新增/去重/非法规则拒)、无 file 400、空库导出。
"""
import io
import unittest

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo


class FingerprintIOTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        set_repo(FakeRepo())

    def tearDown(self):
        reset_repo()

    def _add(self, name, rule):
        return self.client.post("/api/fingerprint/", json={"name": name, "human_rule": rule})

    def test_export_yaml_stream(self):
        self._add("泛微OA", 'body="weaver"')
        r = self.client.get("/api/fingerprint/export/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get("Content-Type"), "application/octet-stream")
        self.assertIn("attachment", r.headers.get("Content-Disposition", ""))
        body = r.get_data(as_text=True)
        self.assertIn("泛微OA", body)
        self.assertIn('body="weaver"', body)

    def test_export_empty_ok(self):
        r = self.client.get("/api/fingerprint/export/")
        self.assertEqual(r.status_code, 200)   # 空库也返 200（空 YAML）

    def test_upload_import_counts(self):
        self._add("泛微OA", 'body="weaver"')   # 预置一条，制造去重
        yml = ('- name: Nacos\n  rule: body="nacos"\n'
               '- name: dup\n  rule: body="weaver"\n'          # 与预置重复 → repeat
               '- name: bad\n  rule: "__import__(\'os\')"\n'   # 非法规则 → error(ast 白名单拒)
               '- name: noname\n  rule: ""\n')                 # 空规则 → error
        r = self.client.post("/api/fingerprint/upload/",
                             data={"file": (io.BytesIO(yml.encode()), "fp.yml")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()["data"]
        self.assertEqual(d["success_cnt"], 1)   # 仅 Nacos 新增
        self.assertEqual(d["repeat_cnt"], 1)    # weaver 去重
        self.assertEqual(d["error_cnt"], 2)     # 非法规则 + 空规则

    def test_upload_no_file_400(self):
        r = self.client.post("/api/fingerprint/upload/",
                             data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_upload_non_list_yaml_400(self):
        yml = "name: notalist\nrule: x\n"   # 顶层是 dict 非 list
        r = self.client.post("/api/fingerprint/upload/",
                             data={"file": (io.BytesIO(yml.encode()), "fp.yml")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_upload_then_export_roundtrip(self):
        yml = '- name: RoundTrip\n  rule: title="rt"\n'
        self.client.post("/api/fingerprint/upload/",
                         data={"file": (io.BytesIO(yml.encode()), "fp.yml")},
                         content_type="multipart/form-data")
        body = self.client.get("/api/fingerprint/export/").get_data(as_text=True)
        self.assertIn("RoundTrip", body)
        self.assertIn('title="rt"', body)


if __name__ == "__main__":
    unittest.main()
