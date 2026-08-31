#!/usr/bin/env python3
"""Run the deterministic Srhino daily pipeline.

The wrapper chooses yesterday's input when present; otherwise it uses the
newest dated Srhino JSONL file, which keeps the demo usable before real feeds
are connected. Model output is written separately by the Agent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import subprocess


DATE_RE = re.compile(r"srhino-alerts-(\d{4}-\d{2}-\d{2})\.jsonl$")


def choose_input(input_dir: pathlib.Path, requested: str | None) -> tuple[pathlib.Path, str]:
    files = []
    for path in input_dir.glob("srhino-alerts-*.jsonl"):
        match = DATE_RE.search(path.name)
        if match:
            files.append((match.group(1), path))
    if not files:
        raise FileNotFoundError(f"未找到 Srhino 告警文件: {input_dir}")
    if requested:
        target = input_dir / f"srhino-alerts-{requested}.jsonl"
        if target.exists():
            return target, requested
    yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    target = input_dir / f"srhino-alerts-{yesterday}.jsonl"
    if target.exists():
        return target, yesterday
    return max(files, key=lambda item: item[0])[1], max(files, key=lambda item: item[0])[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="运行 Srhino 自动日期聚合流水线")
    parser.add_argument("--input-dir", type=pathlib.Path, default=pathlib.Path("data"))
    parser.add_argument("--date")
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path("reports/srhino"))
    args = parser.parse_args()
    source, report_date = choose_input(args.input_dir, args.date)
    command = ["python3", "tools/aggregate_alerts.py", "--input", str(source), "--date", report_date, "--output-dir", str(args.output_dir)]
    subprocess.run(command, check=True)
    review_input = args.output_dir / f"{report_date}-ai-review-input.jsonl"
    # Keep full HTTP evidence available for the model and for audit review.
    lines = source.read_text(encoding="utf-8").splitlines()
    selected = []
    import json
    for line in lines:
        if line.strip():
            event = json.loads(line)
            if event.get("analyst_requested") and event.get("evidence_level") == "full_http":
                selected.append(event)
    review_input.parent.mkdir(parents=True, exist_ok=True)
    review_input.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in selected) + ("\n" if selected else ""), encoding="utf-8")
    print(json.dumps({"date": report_date, "input": str(source), "review_candidates": len(selected), "summary": str(args.output_dir / f"{report_date}-alert-summary.json"), "review_input": str(review_input)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
