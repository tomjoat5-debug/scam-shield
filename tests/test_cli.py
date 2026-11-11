"""命令行测试：报告格式 + 真实调用冒烟测试。"""

import subprocess
import sys
import unittest
from pathlib import Path

from scam_shield.cli import format_report
from scam_shield.engine import analyze

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestFormatReport(unittest.TestCase):
    def test_high_risk_report_has_conclusion_first(self):
        result = analyze(
            "您好，这里是市公安局，您涉嫌一起洗钱案件。"
            "请立即将资金转入安全账户配合调查，案件保密，不要告诉任何人。"
        )
        report = format_report(result)
        self.assertIn("【结论】", report)
        self.assertIn("极高风险", report)
        self.assertIn("冒充公检法", report)
        self.assertIn("【该怎么办】", report)
        self.assertIn("96110", report)
        # 结论在最前面
        self.assertLess(report.index("【结论】"), report.index("【为什么这么判断】"))

    def test_low_risk_report(self):
        result = analyze("【菜鸟】您的快递已送达丰巢快递柜，请凭取件码123456及时取件。")
        report = format_report(result)
        self.assertIn("低风险", report)
        self.assertIn("96110", report)


class TestCliSmoke(unittest.TestCase):
    def test_cli_with_argument(self):
        proc = subprocess.run(
            [sys.executable, "-m", "scam_shield", "恭喜您中奖了，先交500元保证金即可领奖"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("【结论】", proc.stdout)
        self.assertIn("中奖领奖", proc.stdout)

    def test_cli_with_stdin(self):
        proc = subprocess.run(
            [sys.executable, "-m", "scam_shield"],
            input="妈，今天降温了，多穿点衣服，晚上回家吃饭。",
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("低风险", proc.stdout)

    def test_cli_no_input_prints_usage(self):
        proc = subprocess.run(
            [sys.executable, "-m", "scam_shield"],
            input="",
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("用法", proc.stdout)


if __name__ == "__main__":
    unittest.main()
