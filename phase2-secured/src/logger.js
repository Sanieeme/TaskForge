// logger.js — Phase 2
// Minimal structured logging, addressing the "ongoing monitoring" gap
// previously documented as missing in SECURITY_ANALYSIS.md / ITERATION2_
// SECURE_CODING.md. Every log line is a single JSON object on stdout so it
// can be shipped to a real log aggregator (e.g. CloudWatch, Datadog, an ELK
// stack) in production without any code change here - only the transport
// changes, not the call sites.
"use strict";

function baseLog(level, event, meta = {}) {
  const line = {
    ts: new Date().toISOString(),
    level,
    event,
    ...meta,
  };
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(line));
}

function info(event, meta) {
  baseLog("info", event, meta);
}

function warn(event, meta) {
  baseLog("warn", event, meta);
}

// ALERT-level: a real deployment would wire this to a paging/alerting
// system (PagerDuty, an Slack webhook, etc). Here it's still just
// structured stdout, but it's the single call site that would change.
function alert(event, meta) {
  baseLog("alert", event, meta);
}

module.exports = { info, warn, alert };
