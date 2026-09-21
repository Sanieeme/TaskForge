// src/services/audit-service.js
// Addresses the STRIDE Repudiation gap: every state-changing action is
// recorded with who did it, what they did, and when. Living here (rather
// than inline in each controller) means every controller records audit
// events the same way, through the same failure-handling path.
"use strict";

const db = require("../db");
const logger = require("../logger");

function logAudit({ actorId, actorUsername, action, targetType, targetId, detail }) {
  try {
    db.prepare(
      "INSERT INTO audit_log (actor_id, actor_username, action, target_type, target_id, detail) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(actorId, actorUsername, action, targetType, targetId ?? null, detail ?? null);
  } catch (e) {
    // Audit logging must never break the request it's logging.
    logger.warn("audit_log_write_failed", { error: e.message });
  }
  logger.info("audit_event", { actorId, actorUsername, action, targetType, targetId });
}

module.exports = { logAudit };
