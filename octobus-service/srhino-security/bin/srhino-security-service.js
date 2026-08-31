#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { defineService, runServiceMain } from "@chaitin-ai/octobus-sdk";

function loadAlerts(ctx) {
  const file = ctx.config?.dataFile;
  if (!file || !fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

const service = defineService({ handlers: {
  "security.srhino.v1.SrhinoSecurityService/ListSrhinoAlerts": (ctx) => {
    const date = String(ctx.request.reportDate || "");
    const alerts = loadAlerts(ctx).filter((x) => !date || String(x.timestamp).startsWith(date));
    return { alerts: alerts.map((x) => ({ eventId: x.event_id, timestamp: x.timestamp, severity: x.severity, alertName: x.alert_name, sourceIp: x.source_ip, destinationAsset: x.destination_asset, action: x.disposition_action || x.action })) };
  },
  "security.srhino.v1.SrhinoSecurityService/GetSrhinoAlertEvidence": (ctx) => {
    const item = loadAlerts(ctx).find((x) => x.event_id === ctx.request.eventId);
    return item ? { eventId: item.event_id, rawRequest: item.raw_request || "", rawResponse: item.raw_response || "", evidenceLevel: item.evidence_level || "metadata" } : { eventId: ctx.request.eventId, rawRequest: "", rawResponse: "", evidenceLevel: "not_found" };
  },
  "security.srhino.v1.SrhinoSecurityService/CreateAlertReviewTask": (ctx) => ({ taskId: `SRHINO-REVIEW-${ctx.request.eventId}`, eventId: ctx.request.eventId, status: "pending_human_confirmation", message: ctx.request.recommendation || ctx.request.reason || "等待值守人员确认" }),
  "security.srhino.v1.SrhinoSecurityService/SendSrhinoDutyReport": (ctx) => {
    const reportId = `SRHINO-REPORT-${ctx.request.reportDate || new Date().toISOString().slice(0, 10)}`;
    const dir = ctx.config?.reportDir || process.env.OCTOBUS_WORKDIR || process.cwd();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${reportId}.md`), ctx.request.content || "", { mode: 0o600 });
    return { reportId, status: "saved", message: "Srhino值守日报已保存" };
  }
}});

runServiceMain(service);
