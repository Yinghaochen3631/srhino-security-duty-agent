#!/usr/bin/env bash
set -euo pipefail

BASE="/opt/agent-compose/data/work/srhino-duty-agent"
REPORT_DIR="$BASE/reports/srhino"
TOOL_DIR="$BASE/tools"
ENV_FILE="/opt/agent-compose/.env"

# Load only the root-owned deployment environment; credentials never enter the audit log.
set -a
. "$ENV_FILE"
set +a

MD="$(find "$REPORT_DIR" -maxdepth 1 -type f -name '*-duty-report.md' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
if [ -z "$MD" ]; then
  echo '{"status":"no_report","message":"未找到可发送的 Markdown 日报"}'
  exit 0
fi
DATE="$(basename "$MD" | cut -d- -f1-3)"
HTML="$REPORT_DIR/${DATE}-duty-report.html"
python3 "$TOOL_DIR/render_srhino_html.py" --input "$MD" --output "$HTML" --title "Srhino安全告警值守日报"
# Keep the final pair beside the OctoBus report artifact as well as the Agent workspace.
OCTO_REPORT_DIR="/opt/octobus-data/srhino-service/reports"
mkdir -p "$OCTO_REPORT_DIR"
cp "$MD" "$OCTO_REPORT_DIR/SRHINO-REPORT-${DATE}.md"
cp "$HTML" "$OCTO_REPORT_DIR/SRHINO-REPORT-${DATE}.html"
RESULT="$(python3 "$TOOL_DIR/send_srhino_email.py" --html "$HTML" --markdown "$MD" --date "$DATE" --recipient "1622363185@qq.com")"
printf '%s\n' "$RESULT"
printf '{"ts":"%s","date":"%s","kind":"email_send_host","result":%s}\n' "$(date -Is)" "$DATE" "$RESULT" >> "$REPORT_DIR/${DATE}-email-audit.jsonl"
