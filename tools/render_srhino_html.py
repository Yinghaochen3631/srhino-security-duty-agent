#!/usr/bin/env python3
"""Render a Srhino Markdown duty report as a safe, self-contained HTML file."""
from __future__ import annotations

import argparse
import html
import pathlib
import re


def inline(text: str) -> str:
    value = html.escape(text, quote=True)
    value = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
    value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
    return value


def hourly_chart(marker: str) -> str:
    pairs = []
    for token in marker.removeprefix("<!-- SRHINO_HOURLY_CHART:").removesuffix(" -->").split(","):
        if ":" in token:
            hour, count = token.split(":", 1)
            try:
                pairs.append((hour, int(count)))
            except ValueError:
                continue
    if not pairs:
        return ""
    width, height = 820, 280
    left, right, top, bottom = 48, 790, 24, 232
    peak = max(count for _, count in pairs) or 1
    points = []
    for index, (_, count) in enumerate(pairs):
        x = left + (right - left) * index / max(len(pairs) - 1, 1)
        y = bottom - (bottom - top) * count / peak
        points.append((x, y, count))
    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in points)
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5"><title>{hour}:00 {count} 条</title></circle>' for (hour, _), (x, y, count) in zip(pairs, points))
    labels = "".join(f'<text x="{point[0]:.1f}" y="260" text-anchor="middle">{hour}</text>' for index, ((hour, _), point) in enumerate(zip(pairs, points)) if index % 3 == 0)
    grid = "".join(f'<line x1="{left}" y1="{y}" x2="{right}" y2="{y}" />' for y in (top, (top + bottom) / 2, bottom))
    return f'''<div class="chart-card"><div class="chart-title">24小时告警趋势（峰值 {peak} 条）</div><svg class="hourly-chart" viewBox="0 0 {width} {height}" role="img" aria-label="24小时告警数量折线图"><g class="chart-grid">{grid}</g><polyline points="{polyline}" /><g class="chart-dots">{dots}</g><g class="chart-labels">{labels}</g></svg></div>'''


def render(markdown: str, title: str) -> str:
    body: list[str] = []
    paragraph: list[str] = []
    in_list = False
    in_table = False
    in_code = False
    code_lines: list[str] = []
    in_ai_card = False

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            body.append(f"<p>{' '.join(paragraph)}</p>")
            paragraph = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            body.append("</ul>")
            in_list = False

    def close_table() -> None:
        nonlocal in_table
        if in_table:
            body.append("</tbody></table>")
            in_table = False

    def close_ai_card() -> None:
        nonlocal in_ai_card
        if in_ai_card:
            body.append("</section>")
            in_ai_card = False

    for raw in markdown.splitlines():
        line = raw.strip()
        if line.startswith("```"):
            flush_paragraph()
            close_list()
            close_table()
            if in_code:
                body.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(raw.rstrip())
            continue
        if not line:
            flush_paragraph()
            close_list()
            close_table()
            continue
        if line.startswith("<!-- SRHINO_HOURLY_CHART:"):
            flush_paragraph()
            close_list()
            close_table()
            body.append(hourly_chart(line))
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            flush_paragraph()
            close_list()
            close_table()
            if len(heading.group(1)) <= 2:
                close_ai_card()
            level = len(heading.group(1))
            if level == 3 and "SRHINO-" in heading.group(2):
                close_ai_card()
                body.append('<section class="ai-card">')
                in_ai_card = True
            body.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            continue
        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            close_list()
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                continue
            if not in_table:
                body.append("<table><thead><tr>" + "".join(f"<th>{inline(cell)}</th>" for cell in cells) + "</tr></thead><tbody>")
                in_table = True
            else:
                body.append("<tr>" + "".join(f"<td>{inline(cell)}</td>" for cell in cells) + "</tr>")
            continue
        close_table()
        bullet = re.match(r"^[-*]\s+(.*)$", line)
        if bullet:
            flush_paragraph()
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{inline(bullet.group(1))}</li>")
            continue
        if line.startswith(">"):
            flush_paragraph()
            close_list()
            body.append(f"<blockquote>{inline(line[1:].strip())}</blockquote>")
            continue
        flush_paragraph() if line.startswith("---") else None
        if line.startswith("---"):
            close_list()
            body.append("<hr>")
            continue
        close_list()
        paragraph.append(inline(line))

    if in_code:
        body.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
    close_table()
    close_ai_card()
    flush_paragraph()
    close_list()
    escaped_title = html.escape(title, quote=True)
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escaped_title}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#1f2937;line-height:1.65;max-width:1120px;margin:0 auto;padding:22px;background:#eef2f6}}
main{{background:#fff;border:1px solid #d6dee8;padding:24px 30px;box-shadow:0 3px 12px rgba(15,23,42,.07)}}
h1{{font-size:27px;margin:0 0 8px;border-bottom:3px solid #1d4ed8;padding-bottom:12px;color:#0f172a}}h2{{font-size:19px;color:#1d4ed8;margin:30px 0 10px;padding:8px 12px;border-left:5px solid #2563eb;background:#eff6ff}}h3{{font-size:16px;color:#334155;margin-top:24px;padding:8px 10px;background:#f8fafc;border-bottom:1px solid #dbe4ee}}
table{{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}}th{{background:#1e3a8a;color:#fff;text-align:left;font-weight:600}}th,td{{border:1px solid #d7e0ea;padding:8px 10px;vertical-align:top}}tbody tr:nth-child(even){{background:#f8fafc}}tbody tr:hover{{background:#eef6ff}}td:nth-child(2){{font-variant-numeric:tabular-nums;font-weight:600}}
.chart-card{{margin:10px 0 24px;padding:14px 16px;border:1px solid #d7e0ea;background:#fbfdff;border-radius:5px}}.chart-title{{font-weight:600;color:#334155;margin-bottom:4px}}.hourly-chart{{display:block;width:100%;height:auto;min-height:220px}}.hourly-chart polyline{{fill:none;stroke:#2563eb;stroke-width:3;stroke-linejoin:round;stroke-linecap:round}}.chart-grid line{{stroke:#dbe4ee;stroke-width:1}}.chart-dots circle{{fill:#fff;stroke:#2563eb;stroke-width:2}}.chart-labels text{{fill:#64748b;font:12px sans-serif}}
ul{{padding-left:24px}}li{{margin:5px 0;font-size:15px}}code{{background:#eef2f7;border-radius:3px;padding:1px 4px;font-family:Consolas,monospace;font-size:.92em}}pre{{background:#0b1324;color:#f8fafc;border:1px solid #1e3a5f;border-radius:5px;padding:16px;overflow:auto;font:13px/1.6 Consolas,monospace;white-space:pre-wrap;letter-spacing:.1px}}pre code{{background:transparent;color:#f8fafc;padding:0;font:inherit}}.ai-card{{margin:18px 0 24px;padding:4px 18px 14px;border:1px solid #d7e0ea;border-left:5px solid #64748b;background:#fff;box-shadow:0 2px 6px rgba(15,23,42,.04)}}
blockquote{{border-left:4px solid #93c5fd;margin:12px 0;padding:8px 14px;background:#eff6ff;color:#334155}}strong{{color:#b91c1c}}hr{{border:0;border-top:1px solid #d9e0e7;margin:20px 0}}
@media(max-width:640px){{body{{padding:8px}}main{{padding:18px}}}}
</style></head><body><main>{''.join(body)}</main></body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="将 Srhino Markdown 日报转换为 HTML")
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--title", default="Srhino安全告警值守日报")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(args.input.read_text(encoding="utf-8"), args.title), encoding="utf-8")
    print(f"HTML_REPORT={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
