#!/usr/bin/env python3
"""Generate deterministic, sanitized Srhino security-device alert data.

The first five records are deliberately marked as analyst-requested evidence
and include complete (sanitized) HTTP request/response excerpts.  The expected
labels are written to a separate file for evaluator verification only; they
are never sent to the model as input.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import random


TEMPLATES = [
    {"name": "SQL注入攻击", "category": "sqli", "rule": "SQLI-942100", "severity": "high", "action": ["block", "block", "challenge"], "code": 403, "uris": ["/api/auth/login", "/api/search", "/product/list"]},
    {"name": "跨站脚本攻击", "category": "xss", "rule": "XSS-941100", "severity": "medium", "action": ["block", "challenge", "allow"], "code": 403, "uris": ["/comment/submit", "/search", "/user/profile"]},
    {"name": "暴力破解登录", "category": "brute-force", "rule": "BRUTE-913100", "severity": "high", "action": ["challenge", "challenge", "allow"], "code": 429, "uris": ["/api/auth/login", "/admin/login"]},
    {"name": "恶意扫描探测", "category": "scanner", "rule": "SCANNER-980130", "severity": "low", "action": ["block", "block", "allow"], "code": 403, "uris": ["/.env", "/actuator/env", "/wp-admin"]},
    {"name": "路径穿越攻击", "category": "path-traversal", "rule": "LFI-930110", "severity": "high", "action": ["block", "block", "challenge"], "code": 403, "uris": ["/download", "/api/file", "/static"]},
    {"name": "敏感数据暴露检测", "category": "data-exposure", "rule": "API-EXPOSE-001", "severity": "high", "action": ["allow", "allow", "challenge"], "code": 200, "uris": ["/api/user/export", "/api/order/detail", "/api/report"]},
    {"name": "API异常频率", "category": "api-abuse", "rule": "API-RATE-001", "severity": "medium", "action": ["challenge", "challenge", "allow"], "code": 429, "uris": ["/api/search", "/api/message", "/api/order"]},
]

SOURCE_IPS = ["203.0.113.10", "203.0.113.11", "198.51.100.20", "198.51.100.21", "192.0.2.50", "192.0.2.51"]
ASSETS = ["web-prod-01", "web-prod-02", "api-prod-01", "api-prod-02", "oa-prod-01"]
RECIPIENTS = {
    "web-prod-01": "Web应用责任单位",
    "web-prod-02": "Web应用责任单位",
    "api-prod-01": "API平台主管单位",
    "api-prod-02": "API平台主管单位",
    "oa-prod-01": "OA系统责任单位",
}


def event_time(rng: random.Random, report_date: str) -> str:
    hour = rng.choices([0, 1, 2, 7, 8, 9, 10, 11, 12, 14, 16, 18, 20, 22, 23], weights=[2, 1, 1, 3, 4, 7, 18, 17, 7, 3, 2, 4, 5, 14, 13])[0]
    return f"{report_date}T{hour:02d}:{rng.randrange(60):02d}:{rng.randrange(60):02d}+08:00"


def make_event(index: int, report_date: str, rng: random.Random, severity: str | None = None) -> dict:
    # Keep the demo distribution realistic: high < medium < low.
    candidates = [item for item in TEMPLATES if severity is None or item["severity"] == severity]
    template = rng.choice(candidates)
    source_ip = rng.choices(SOURCE_IPS, weights=[34, 22, 16, 12, 9, 7])[0]
    asset = rng.choice(ASSETS)
    action = rng.choice(template["action"])
    uri = rng.choice(template["uris"])
    timestamp = event_time(rng, report_date)
    marker = hashlib.sha256(f"{index}:{source_ip}:{uri}".encode()).hexdigest()[:12]
    if action == "block":
        handling_status = "已拦截"
        closed_loop_status = "已闭环"
    elif severity == "high":
        handling_status = "已下发风险预警"
        closed_loop_status = "已闭环"
    elif severity == "low":
        handling_status = "已完成观察"
        closed_loop_status = "已闭环"
    else:
        handling_status = "待人工复核"
        closed_loop_status = "待复核"
    warning_issued = action == "block" or severity == "high"
    return {
        "event_id": f"SRHINO-{report_date.replace('-', '')}-{index:05d}",
        "timestamp": timestamp,
        "device": "Srhino安全运营平台演示设备",
        "event_type": "security_alert",
        "alert_name": template["name"],
        "attack_category": template["category"],
        "severity": template["severity"],
        "source_ip": source_ip,
        "destination_asset": asset,
        "host": f"{asset}.example.test",
        "uri": uri,
        "method": rng.choice(["GET", "POST"]),
        "action": action,
        "disposition_action": {"block": "拦截", "challenge": "人机校验", "allow": "放行观察"}[action],
        "challenge_result": ("未通过" if action == "challenge" and index % 2 else ("通过" if action == "challenge" else "不适用")),
        "handling_status": handling_status,
        "closed_loop_status": closed_loop_status,
        "warning_issued": warning_issued,
        "warning_status": "已下发" if warning_issued else "未下发",
        "warning_recipient": RECIPIENTS[asset] if warning_issued else "",
        "warning_issued_at": timestamp if warning_issued else "",
        "status": "blocked" if action == "block" else ("challenged" if action == "challenge" else "allowed"),
        "status_code": template["code"] if action != "allow" else 200,
        "hit_count": 1,
        "rule_id": template["rule"],
        "request_id": f"req-{marker}",
        "analyst_requested": False,
        "evidence_level": "metadata",
        "evidence": {"signature": template["rule"], "sanitized_marker": marker, "user_agent": "demo-client/1.0"},
    }


def review_samples(report_date: str) -> tuple[list[dict], list[dict]]:
    """Return five full-evidence events and labels kept outside model input."""
    base = f"{report_date}T09:"
    samples = [
        {
            "event_id": f"SRHINO-{report_date.replace('-', '')}-R001", "timestamp": base + "12:04+08:00",
            "alert_name": "SQL注入攻击", "attack_category": "sqli", "severity": "high", "source_ip": "203.0.113.10", "destination_asset": "api-prod-01", "uri": "/api/auth/login", "method": "POST", "action": "block", "status": "blocked", "status_code": 403, "rule_id": "SQLI-942100",
            "raw_request": "POST /api/auth/login HTTP/1.1\nHost: api-prod-01.example.test\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: demo-client/1.0\n\nusername=admin%27+OR+%271%27%3D%271&password=demo",
            "raw_response": "HTTP/1.1 403 Forbidden\nContent-Type: application/json\nX-Srhino-Action: block\n\n{\"code\":403,\"message\":\"request blocked\"}",
            "expected_verdict": "真实攻击", "expected_reason": "登录参数包含典型恒真条件，且设备已拦截。", "expected_next_step": "保持拦截，核查账号登录失败次数并检查相关账号是否需要重置密码。",
        },
        {
            "event_id": f"SRHINO-{report_date.replace('-', '')}-R002", "timestamp": base + "10:37:51+08:00",
            "alert_name": "路径穿越攻击", "attack_category": "path-traversal", "severity": "high", "source_ip": "198.51.100.20", "destination_asset": "web-prod-02", "uri": "/download?file=../../../../etc/passwd", "method": "GET", "action": "block", "status": "blocked", "status_code": 403, "rule_id": "LFI-930110",
            "raw_request": "GET /download?file=../../../../etc/passwd HTTP/1.1\nHost: web-prod-02.example.test\nAccept: */*\nUser-Agent: security-scanner/2.1\n\n",
            "raw_response": "HTTP/1.1 403 Forbidden\nContent-Type: text/plain\nX-Srhino-Action: block\n\nblocked by security policy",
            "expected_verdict": "真实攻击", "expected_reason": "请求试图读取系统口令文件，路径穿越意图明确。", "expected_next_step": "保持拦截，核查目标主机文件访问日志并确认下载接口已完成路径校验。",
        },
        {
            "event_id": f"SRHINO-{report_date.replace('-', '')}-R003", "timestamp": base + "11:46:22+08:00",
            "alert_name": "暴力破解登录", "attack_category": "brute-force", "severity": "high", "source_ip": "192.0.2.50", "destination_asset": "oa-prod-01", "uri": "/admin/login", "method": "POST", "action": "challenge", "status": "challenged", "status_code": 429, "rule_id": "BRUTE-913100",
            "raw_request": "POST /admin/login HTTP/1.1\nHost: oa-prod-01.example.test\nContent-Type: application/json\nX-Forwarded-For: 192.0.2.50\n\n{\"username\":\"admin\",\"password\":\"guess-017\"}",
            "raw_response": "HTTP/1.1 429 Too Many Requests\nContent-Type: application/json\nRetry-After: 60\nX-Srhino-Action: challenge\n\n{\"error\":\"verification_required\"}",
            "expected_verdict": "真实攻击", "expected_reason": "管理端登录连续猜测密码，触发频率控制并被挑战。", "expected_next_step": "将挑战升级为临时拦截并核查管理员账号、源 IP 和 MFA 登录记录。",
        },
        {
            "event_id": f"SRHINO-{report_date.replace('-', '')}-R004", "timestamp": base + "08:15:09+08:00",
            "alert_name": "跨站脚本攻击", "attack_category": "xss", "severity": "medium", "source_ip": "203.0.113.11", "destination_asset": "web-prod-01", "uri": "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "method": "GET", "action": "allow", "status": "allowed", "status_code": 200, "rule_id": "XSS-941100",
            "raw_request": "GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\nHost: web-prod-01.example.test\nUser-Agent: Mozilla/5.0 (compatible; demo-browser)\n\n",
            "raw_response": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nX-Srhino-Action: allow\n\n<html><body>Search results for &lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
            "expected_verdict": "疑似误报", "expected_reason": "应用对输入进行了 HTML 实体编码，响应未执行脚本，业务搜索正常返回。", "expected_next_step": "暂不封禁，通知 Web 应用责任单位确认输出编码和规则例外，观察同类请求。",
        },
        {
            "event_id": f"SRHINO-{report_date.replace('-', '')}-R005", "timestamp": base + "09:02:44+08:00",
            "alert_name": "SQL注入攻击", "attack_category": "sqli", "severity": "medium", "source_ip": "198.51.100.21", "destination_asset": "api-prod-02", "uri": "/api/order/search", "method": "POST", "action": "allow", "status": "allowed", "status_code": 200, "rule_id": "SQLI-942100",
            "raw_request": "POST /api/order/search HTTP/1.1\nHost: api-prod-02.example.test\nContent-Type: application/json\nX-Request-Id: demo-r005\n\n{\"keyword\":\"select shoes\",\"sort\":\"price asc\"}",
            "raw_response": "HTTP/1.1 200 OK\nContent-Type: application/json\nX-Srhino-Action: allow\n\n{\"total\":2,\"items\":[{\"name\":\"select shoes\",\"price\":199}]}",
            "expected_verdict": "疑似误报", "expected_reason": "SQL 关键词出现在合法商品搜索词中，参数为普通字符串且响应为正常业务结果。", "expected_next_step": "暂不封禁，通知 API平台主管单位核对参数化查询和业务关键词白名单。",
        },
    ]
    events = []
    labels = []
    for sample in samples:
        label = {"event_id": sample.pop("event_id"), "expected_verdict": sample.pop("expected_verdict"), "expected_reason": sample.pop("expected_reason"), "expected_next_step": sample.pop("expected_next_step")}
        action, severity, asset = sample["action"], sample["severity"], sample["destination_asset"]
        sample_handling = "已拦截" if action == "block" else ("已下发风险预警" if severity == "high" else "待人工复核")
        sample_closed = "已闭环" if action == "block" else "待复核"
        sample_warning = action == "block" or severity == "high"
        sample.update({"event_id": label["event_id"], "device": "Srhino安全运营平台演示设备", "event_type": "security_alert", "host": asset + ".example.test", "request_id": "req-" + label["event_id"], "hit_count": 1, "analyst_requested": True, "evidence_level": "full_http", "disposition_action": {"block": "拦截", "challenge": "人机校验", "allow": "放行观察"}[action], "challenge_result": "未通过" if action == "challenge" else "不适用", "handling_status": sample_handling, "closed_loop_status": sample_closed, "warning_issued": sample_warning, "warning_status": "已下发" if sample_warning else "未下发", "warning_recipient": RECIPIENTS[asset] if sample_warning else "", "warning_issued_at": sample["timestamp"] if sample_warning else "", "evidence": {"signature": sample["rule_id"], "collection_reason": "人工点击AI研判", "sanitized": True}})
        events.append(sample)
        labels.append(label)
    return events, labels


def main() -> int:
    parser = argparse.ArgumentParser(description="生成脱敏 Srhino 安全设备告警 JSONL/CSV 演示数据")
    parser.add_argument("--date", default="2026-08-28")
    parser.add_argument("--count", type=int, default=240)
    parser.add_argument("--jsonl", required=True, type=pathlib.Path)
    parser.add_argument("--csv", type=pathlib.Path)
    parser.add_argument("--review-jsonl", type=pathlib.Path)
    parser.add_argument("--labels", type=pathlib.Path)
    args = parser.parse_args()
    if args.count < 5:
        raise SystemExit("--count 必须至少为 5，以包含人工研判样本")
    rng = random.Random(20260828)
    samples, labels = review_samples(args.date)
    target_high = max(3, args.count // 6)
    target_medium = max(2, args.count // 3)
    target_low = args.count - target_high - target_medium
    if target_low <= target_medium:
        target_low = target_medium + 1
        target_high = args.count - target_medium - target_low
    sample_counts = {"high": 3, "medium": 2, "low": 0}
    severity_plan = []
    for level, target in (("high", target_high), ("medium", target_medium), ("low", target_low)):
        severity_plan.extend([level] * max(0, target - sample_counts[level]))
    while len(severity_plan) < args.count - len(samples):
        severity_plan.append("low")
    severity_plan = severity_plan[: args.count - len(samples)]
    rng.shuffle(severity_plan)
    events = samples + [make_event(i, args.date, rng, severity_plan[i - 6]) for i in range(6, args.count + 1)]
    args.jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.jsonl.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    columns = ["event_id", "timestamp", "device", "event_type", "alert_name", "attack_category", "severity", "source_ip", "destination_asset", "host", "uri", "method", "action", "disposition_action", "challenge_result", "status", "status_code", "handling_status", "closed_loop_status", "warning_issued", "warning_status", "warning_recipient", "warning_issued_at", "hit_count", "rule_id", "request_id", "analyst_requested", "evidence_level", "raw_request", "raw_response"]
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows({key: event.get(key, "") for key in columns} for event in events)
    if args.review_jsonl:
        args.review_jsonl.parent.mkdir(parents=True, exist_ok=True)
        args.review_jsonl.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in samples) + "\n", encoding="utf-8")
    if args.labels:
        args.labels.parent.mkdir(parents=True, exist_ok=True)
        args.labels.write_text(json.dumps({"date": args.date, "labels": labels}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"date": args.date, "events": len(events), "full_evidence": len(samples), "jsonl": str(args.jsonl), "csv": str(args.csv) if args.csv else None, "review_jsonl": str(args.review_jsonl) if args.review_jsonl else None, "labels": str(args.labels) if args.labels else None}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
