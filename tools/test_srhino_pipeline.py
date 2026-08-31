#!/usr/bin/env python3
"""Small regression tests for the Srhino deterministic pipeline."""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from aggregate_alerts import aggregate, evaluate_rule, load, load_rules, markdown
from run_srhino_pipeline import choose_input


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SrhinoPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = ROOT / "data/srhino-alerts-2026-08-28.jsonl"
        self.events = load(self.path, "2026-08-28")

    def test_distribution_and_review_samples(self) -> None:
        summary = aggregate(self.events, "2026-08-28")
        self.assertEqual(summary["event_count"], 240)
        self.assertEqual(summary["severity_counts"], {"high": 40, "medium": 80, "low": 120})
        self.assertEqual(summary["ai_review_candidate_count"], 5)
        self.assertEqual(sum(summary["disposition_action_counts"].values()), 240)

    def test_closed_loop_accounting_is_explicit(self) -> None:
        summary = aggregate(self.events, "2026-08-28")
        closed = summary["closed_loop_status_counts"]
        handling = summary["handling_status_counts"]
        self.assertEqual(closed["已闭环"] + closed["待复核"], 240)
        self.assertEqual(closed["已闭环"], 176)
        self.assertAlmostEqual(summary["closed_loop_rate"], 176 / 240, places=3)
        self.assertGreater(handling["已完成观察"], 0)

    def test_full_http_evidence_is_complete(self) -> None:
        candidates = [e for e in self.events if e.get("analyst_requested")]
        self.assertEqual(len(candidates), 5)
        self.assertTrue(all(e.get("raw_request") and e.get("raw_response") for e in candidates))

    def test_domain_rules_are_loaded_and_consumed(self) -> None:
        rules = load_rules()
        self.assertEqual(rules["rules"]["sqli"]["id"], "SRH-SQLI-001")
        by_id = {event["event_id"].rsplit("-", 1)[-1]: event for event in self.events}
        self.assertEqual(evaluate_rule(by_id["R001"], rules)["decision"], "真实攻击尝试")
        self.assertEqual(evaluate_rule(by_id["R002"], rules)["decision"], "真实攻击尝试")
        self.assertEqual(evaluate_rule(by_id["R004"], rules)["decision"], "疑似误报")
        self.assertEqual(evaluate_rule(by_id["R005"], rules)["decision"], "疑似误报")
        incomplete = dict(by_id["R001"])
        incomplete["raw_response"] = ""
        self.assertEqual(evaluate_rule(incomplete, rules)["decision"], "无法判断")

    def test_daily_report_contains_ai_evidence_sections(self) -> None:
        report = markdown(aggregate(self.events, "2026-08-28"))
        self.assertEqual(report.count("AI研判结论"), 5)
        self.assertEqual(report.count("原始请求"), 5)
        self.assertEqual(report.count("原始回包"), 5)
        self.assertIn("| 告警总数 | 240 |", report)
        self.assertIn("## 五、小时趋势", report)
        self.assertIn("## 八、值守结论", report)
        self.assertIn("闭环率 **73.3%**", report)
        self.assertIn("确定性规则预判", report)

    def test_choose_input_prefers_requested_date(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = pathlib.Path(directory)
            (folder / "srhino-alerts-2026-08-28.jsonl").write_text("{}\n", encoding="utf-8")
            selected, date = choose_input(folder, "2026-08-28")
            self.assertEqual(date, "2026-08-28")
            self.assertEqual(selected.name, "srhino-alerts-2026-08-28.jsonl")


if __name__ == "__main__":
    unittest.main()
