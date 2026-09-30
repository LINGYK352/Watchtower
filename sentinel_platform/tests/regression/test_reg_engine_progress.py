"""回归④：AI 渗透空转防护三函数 + 阈值常量（_engine.py:151/176/195, 常量 :28-44）。

事故史（记忆 sentinel-anti-idle-evolution，同一矛盾反复发作 5 阶段）：
- 硬轮数→A1停滞→empty_streak→no_progress→404维度，每次防护被新空转形态绕过。
- 铁律：客观事实(连续空/404占比/finding数)可机械触发；语义判断绝不机械猜(否则误杀绕WAF/越权403→200)。
- EMPTY_STREAK_LIMIT=2 曾被改 3 被否决（sentinel-finding-quality-fixes 砍 P5「2→3 有害」），锁死不许再动。
- 404 维度：疯狂 fuzz 新路径每个 404 让指纹涨→no_progress 永不触发；修=_resp_is_useful 404空壳不算进展，
  但 4xx 带实质 body(>200)仍算（防误杀越权 403→改 cookie 200 这类真进展）。
"""
import unittest

from sentinel_platform.modules.ai_pentest import _engine as E


class ThresholdConstantsRedline(unittest.TestCase):
    """阈值常量红线：防"顺手调阈值"重蹈覆辙。改这些前必读 sentinel-anti-idle-evolution。"""
    def test_empty_streak_limit_is_2(self):
        self.assertEqual(E.EMPTY_STREAK_LIMIT, 2, "EMPTY_STREAK_LIMIT 2→3 已被否决过(P5 有害)，勿改")

    def test_no_progress_soft_only(self):
        """2026-09 决策移除 NO_PROGRESS_HARD 强制收尾：机械按"零增量轮数"掐断会误杀多接口枚举/绕WAF/
        越权(见 sentinel-anti-idle-evolution"语义判断绝不机械猜")。只保留 SOFT 软提醒(不终止)；
        收尾交 AI 自主研判 / empty_streak / 上下文窗口硬边界。HARD 不得复活。"""
        self.assertEqual(E.NO_PROGRESS_SOFT, 20)
        self.assertFalse(hasattr(E, "NO_PROGRESS_HARD"), "NO_PROGRESS_HARD 已按决策移除，不应复活")

    def test_dirbrute_thresholds(self):
        self.assertEqual(E.DIRBRUTE_WINDOW, 30)
        self.assertEqual(E.DIRBRUTE_404_RATIO, 0.75)
        self.assertEqual(E.DIRBRUTE_MIN_SAMPLES, 20)


class RespIsUsefulRegression(unittest.TestCase):
    """_resp_is_useful：http 2xx/3xx 或 4xx/5xx 带实质 body 才算有效；空壳 404 不算。"""
    def test_non_http_always_useful(self):
        self.assertTrue(E._resp_is_useful("collect_js", {"anything": 1}))
        self.assertTrue(E._resp_is_useful("query_vuln_intel", None))

    def test_2xx_3xx_useful(self):
        self.assertTrue(E._resp_is_useful("http_request", {"status_code": 200, "body_length": 0}))
        self.assertTrue(E._resp_is_useful("http_request", {"status_code": 302}))

    def test_404_empty_shell_not_useful(self):
        """空壳 404 不算进展（治 fuzz 绕过 no_progress）。"""
        self.assertFalse(E._resp_is_useful("http_request", {"status_code": 404, "body_length": 50}))

    def test_4xx_with_substantial_body_useful(self):
        """4xx 带实质 body(>200) 算有效——防误杀越权验证(403→改cookie 200)/详细报错泄露。"""
        self.assertTrue(E._resp_is_useful("http_request", {"status_code": 403, "body_length": 800}))

    def test_no_status_lenient(self):
        """无状态码(连接失败等)宽松放行，交网络死轮机制处理，不误伤。"""
        self.assertTrue(E._resp_is_useful("http_request", {"body_length": 0}))


class ProgressFingerprintRegression(unittest.TestCase):
    """_progress_fingerprint：(finding数, 去重的有效响应(工具,目标)对数)。404 不计入。"""
    def test_finding_count_reflected(self):
        self.assertEqual(E._progress_fingerprint([], 3)[0], 3)

    def test_404_urls_do_not_advance(self):
        """30 个不同 URL 全打 404 → 有效目标对数=0（防每个新 404 让指纹涨）。"""
        log = [{"name": "http_request", "arguments": {"url": "http://t/{}".format(i)},
                "result": {"status_code": 404, "body_length": 30}} for i in range(30)]
        self.assertEqual(E._progress_fingerprint(log, 0)[1], 0)

    def test_useful_targets_counted_deduped(self):
        log = [{"name": "http_request", "arguments": {"url": "http://t/a"}, "result": {"status_code": 200}},
               {"name": "http_request", "arguments": {"url": "http://t/a"}, "result": {"status_code": 200}},
               {"name": "http_request", "arguments": {"url": "http://t/b"}, "result": {"status_code": 200}}]
        self.assertEqual(E._progress_fingerprint(log, 0)[1], 2)   # a/b 两个去重目标


class DirbruteSignalRegression(unittest.TestCase):
    """_dirbrute_signal：近 30 次 http 里 404 占比≥0.75 且样本≥20 → True（无脑目录穷举）。"""
    def test_below_min_samples_false(self):
        log = [{"name": "http_request", "result": {"status_code": 404}} for _ in range(19)]
        self.assertFalse(E._dirbrute_signal(log), "样本<20 不判(防少量误判)")

    def test_high_404_ratio_true(self):
        log = [{"name": "http_request", "result": {"status_code": 404}} for _ in range(25)]
        self.assertTrue(E._dirbrute_signal(log))

    def test_sparse_200_does_not_break_signal(self):
        """20×404 + 5×200 → 404 占比 20/25=0.8≥0.75 → 仍 True（治零星 200 打断计数）。"""
        log = [{"name": "http_request", "result": {"status_code": 200}} for _ in range(5)] + \
              [{"name": "http_request", "result": {"status_code": 404}} for _ in range(20)]
        self.assertTrue(E._dirbrute_signal(log))

    def test_mostly_200_not_dirbrute(self):
        log = [{"name": "http_request", "result": {"status_code": 200}} for _ in range(25)]
        self.assertFalse(E._dirbrute_signal(log))


if __name__ == "__main__":
    unittest.main()
