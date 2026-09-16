import { processOneEmail } from "./emailOutbox.service.js";
import { EmailOutboxModel } from "../../models/EmailOutbox.model.js";
import { env } from "../../config/env.js";
import { runRetention } from "../security/retention.service.js";
import { logger } from "../../config/logger.js";

// Publish non-secret queue telemetry for operational alerting.
export async function reportOutboxHealth(): Promise<void> {
  const [pending, oldest] = await Promise.all([
    EmailOutboxModel.countDocuments({ status: "PENDING" }),
    EmailOutboxModel.findOne({ status: "PENDING" })
      .sort({ createdAt: 1 }).select("createdAt").lean(),
  ]);
  const oldestAgeSeconds = oldest
    ? Math.max(0, Math.floor((Date.now() - oldest.createdAt.getTime()) / 1000)) : 0;
  const fields = { pending, oldestAgeSeconds };
  if (pending >= env.OUTBOX_ALERT_BACKLOG || oldestAgeSeconds >= env.OUTBOX_ALERT_AGE_SECONDS) {
    logger.warn(fields, "Email queue threshold exceeded");
  } else logger.info(fields, "Email queue health");
}

export function startMaintenanceWorker(): () => Promise<void> {
  let stopping = false;
  const wakeups = new Set<() => void>();
  // Idle waits are interruptible so shutdown does not wait for a polling interval.
  function pause(ms: number): Promise<void> {
    return new Promise(resolve => {
      const finish = () => { clearTimeout(timer); wakeups.delete(finish); resolve(); };
      const timer = setTimeout(finish, ms);
      wakeups.add(finish);
    });
  }
  async function deliver(): Promise<void> {
    while (!stopping) {
      try {
        // A busy lane claims its next job immediately; leases coordinate instances.
        if (await processOneEmail()) continue;
      } catch (error) {
        logger.error({ err: error, operation: "outbox.delivery" }, "Email delivery maintenance failed");
      }
      if (!stopping) await pause(1000);
    }
  }
  async function maintain(): Promise<void> {
    while (!stopping) {
      try { await reportOutboxHealth(); await runRetention(); }
      catch (error) {
        logger.error({ err: error, operation: "outbox.maintenance" }, "Retention or email telemetry failed");
      }
      if (!stopping) await pause(60_000);
    }
  }
  // Bound simultaneous SMTP operations independently of request and Argon2 work.
  const workers = Array.from({ length: env.OUTBOX_CONCURRENCY }, () => deliver());
  workers.push(maintain());
  return async () => {
    stopping = true;
    for (const wake of wakeups) wake();
    await Promise.all(workers);
  };
}
