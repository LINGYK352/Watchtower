import time
import unittest
from unittest import mock
from sentinel_platform.modules.system import log_monitor as lm
from sentinel_platform.modules.workspace import dashboard as dash

class CpuSampleTest(unittest.TestCase):
    def sample_repo(self, row):
        repo = mock.Mock(); repo.collection.return_value.find_one.return_value = row
        return repo

    def test_shared_sample_is_fresh_each_read_and_zero_is_valid(self):
        row = {"cpu": 0, "ts": time.time()}
        with mock.patch.object(lm, "get_repo", return_value=self.sample_repo(row)):
            self.assertEqual(lm.get_cpu_sample()["cpu"], 0)
            row["cpu"] = 97
            self.assertEqual(lm.get_cpu_sample()["cpu"], 97)

    def test_invalid_or_stale_samples_do_not_replace_a_probe(self):
        now = time.time()
        rows = [None, {}, {"cpu": 25, "ts": now-lm._CPU_SAMPLE_MAX_AGE-1}, {"cpu": 25, "ts": now+20},
                {"cpu": float("nan"), "ts": now}, {"cpu": 101, "ts": now}, {"cpu": -1, "ts": now}]
        for row in rows:
            with self.subTest(row=row), mock.patch.object(lm, "get_repo", return_value=self.sample_repo(row)):
                self.assertIsNone(lm.get_cpu_sample())

    def device(self, sample, legacy=False):
        ps = mock.MagicMock(); ps.cpu_count.return_value=4; ps.cpu_percent.return_value=33
        ps.virtual_memory.return_value=mock.Mock(percent=20,total=100,used=20)
        ps.disk_usage.return_value=mock.Mock(percent=10,total=100,used=10,free=90)
        ps.boot_time.return_value=time.time()-100
        registry=mock.Mock()
        service=mock.Mock(spec=["get_cpu_sample"] if not legacy else [])
        if not legacy:service.get_cpu_sample.return_value=sample
        registry.get.return_value=service
        with mock.patch.object(dash,"_psutil",return_value=ps), mock.patch("sentinel_platform.contracts.get_registry",return_value=registry), \
             mock.patch.object(dash.DashboardServiceImpl,"_exit_ip_info",return_value={}), \
             mock.patch.object(dash.DashboardServiceImpl,"_resource_score",return_value={}), mock.patch("os.getloadavg",return_value=(0,0,0),create=True):
            result=dash.DashboardServiceImpl().device_info()
        return result,ps

    def test_shared_sample_skips_per_request_sleep(self):
        result,ps=self.device({"cpu": 12, "ts": time.time(), "age_seconds": 1})
        ps.cpu_percent.assert_not_called()
        self.assertEqual(result["cpu_percent"],12)
        self.assertEqual(result["cpu_sample_source"],"scheduler")

    def test_missing_or_legacy_service_preserves_blocking_fallback(self):
        for legacy in [False,True]:
            result,ps=self.device(None,legacy=legacy)
            ps.cpu_percent.assert_called_once_with(interval=0.6)
            self.assertEqual(result["cpu_percent"],33)
            self.assertEqual(result["cpu_sample_source"],"local_probe")

if __name__ == "__main__":unittest.main()
