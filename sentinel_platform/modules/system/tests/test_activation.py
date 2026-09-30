"""system/activation 单测 —— 激活凭证单一权威 + 多 worker fresh 读盘。

覆盖：read_key 始终读盘（写后立即生效,不受 config 缓存影响，治多 worker 不一致）、
local_status 时效判定（有效/过期/无 key）、validate_remote 分情况（403→unauthorized / 网络→network）。
"""
import base64
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from sentinel_platform.modules.system import activation


def _jwt(exp_offset: int, name: str = "tester") -> str:
    payload = {"exp": int(time.time()) + exp_offset, "name": name}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiJ9." + seg + ".sig"


class ActivationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="act_")
        self.cfg = os.path.join(self.dir, "config", "config.yaml")
        os.makedirs(os.path.dirname(self.cfg), exist_ok=True)
        self._old_env = os.environ.get("SENTINEL_PLATFORM_CONFIG")
        os.environ["SENTINEL_PLATFORM_CONFIG"] = self.cfg

    def tearDown(self):
        import shutil
        if self._old_env is None:
            os.environ.pop("SENTINEL_PLATFORM_CONFIG", None)
        else:
            os.environ["SENTINEL_PLATFORM_CONFIG"] = self._old_env
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write_key(self, key):
        import yaml
        with open(self.cfg, "w", encoding="utf-8") as f:
            yaml.dump({"UPDATE": {"KEY": key, "SOURCE_URL": "http://x:5080"}}, f)

    def test_read_key_fresh_reflects_disk_immediately(self):
        # 关键：写新 key 后立即读到（fresh 读盘，不经缓存）——治多 worker 一个激活其他没激活
        k1 = _jwt(3600)
        self._write_key(k1)
        self.assertEqual(activation.read_key(), k1)
        k2 = _jwt(7200)                       # 覆盖为新 key（模拟另一次激活）
        self._write_key(k2)
        self.assertEqual(activation.read_key(), k2)   # 立即变，无缓存滞后

    def test_local_status_activated(self):
        self._write_key(_jwt(30 * 86400))
        st = activation.local_status()
        self.assertTrue(st["activated"]); self.assertFalse(st["expired"])
        self.assertGreater(st["remaining_days"], 0); self.assertTrue(st["has_key"])

    def test_local_status_expired(self):
        self._write_key(_jwt(-86400))
        st = activation.local_status()
        self.assertFalse(st["activated"]); self.assertTrue(st["expired"])

    def test_local_status_no_key(self):
        import yaml
        with open(self.cfg, "w", encoding="utf-8") as f:
            yaml.dump({"UPDATE": {}}, f)
        st = activation.local_status()
        self.assertFalse(st["activated"]); self.assertFalse(st["has_key"])

    def test_activation_key_file_fallback(self):
        # config 无 key,但同目录 .activation_key 有 → 读到
        import yaml
        with open(self.cfg, "w", encoding="utf-8") as f:
            yaml.dump({"UPDATE": {}}, f)
        k = _jwt(3600)
        with open(os.path.join(os.path.dirname(self.cfg), ".activation_key"), "w", encoding="utf-8") as f:
            f.write(k)
        self.assertEqual(activation.read_key(), k)

    def test_validate_remote_unauthorized(self):
        self._write_key(_jwt(3600))
        from urllib.error import HTTPError
        import io
        def _raise403(*a, **k):
            raise HTTPError("u", 403, "Forbidden", {}, io.BytesIO(b'{"error":"unknown key"}'))
        with mock.patch.object(activation, "urlopen", side_effect=_raise403):
            r = activation.validate_remote("/version")
        self.assertFalse(r["ok"]); self.assertEqual(r["reason"], "unauthorized")

    def test_validate_remote_network(self):
        self._write_key(_jwt(3600))
        with mock.patch.object(activation, "urlopen", side_effect=OSError("conn refused")):
            r = activation.validate_remote("/version")
        self.assertFalse(r["ok"]); self.assertEqual(r["reason"], "network")

    def test_validate_remote_no_key(self):
        import yaml
        with open(self.cfg, "w", encoding="utf-8") as f:
            yaml.dump({"UPDATE": {}}, f)
        r = activation.validate_remote("/version")
        self.assertFalse(r["ok"]); self.assertEqual(r["reason"], "no_key")

    # —— 激活时钟：remaining_days 用 ceil（v1.21.157-15）——
    def test_remaining_days_ceil_under_one_day(self):
        """剩不到 24h 但未过期 → remaining_days 应为 1（ceil），不再是 0（治假过期）。"""
        self._write_key(_jwt(23 * 3600))   # 剩 23 小时
        st = activation.local_status()
        self.assertTrue(st["activated"])
        self.assertFalse(st["expired"])
        self.assertEqual(st["remaining_days"], 1)

    # —— 云端一票否决：吊销标记（隔离到本用例 tempdir）——
    def _isolate_revoke_paths(self):
        """把吊销标记候选路径限定到本用例 tempdir，避免污染真实 /tmp 或读到残留。"""
        p = os.path.join(self.dir, ".activation_revoked")
        return mock.patch.object(activation, "_revoked_file_candidates", return_value=[p])

    def test_revoke_terminates_clock(self):
        """云端否决：mark_revoked 后即便 JWT 未到期也判 expired（吊销即时生效）。"""
        self._write_key(_jwt(30 * 86400))   # JWT 还剩 30 天
        with self._isolate_revoke_paths():
            self.assertFalse(activation.is_revoked())
            self.assertTrue(activation.local_status()["activated"])
            activation.mark_revoked("remote_unauthorized")
            self.assertTrue(activation.is_revoked())
            st = activation.local_status()
            self.assertFalse(st["activated"])
            self.assertTrue(st["expired"])
            self.assertTrue(st["revoked"])
            self.assertEqual(st["remaining_days"], 0)

    def test_clear_revoked_restores(self):
        self._write_key(_jwt(30 * 86400))
        with self._isolate_revoke_paths():
            activation.mark_revoked()
            activation.clear_revoked()
            self.assertFalse(activation.is_revoked())
            self.assertTrue(activation.local_status()["activated"])

    def test_note_remote_result_semantics(self):
        """unauthorized→落否决；成功('')→清否决；network→不动。"""
        self._write_key(_jwt(30 * 86400))
        with self._isolate_revoke_paths():
            activation.note_remote_result("unauthorized")
            self.assertTrue(activation.is_revoked())
            activation.note_remote_result("network")     # 网络问题不动
            self.assertTrue(activation.is_revoked())
            activation.note_remote_result("")             # 云端重新认可 → 解除
            self.assertFalse(activation.is_revoked())


if __name__ == "__main__":
    unittest.main()
