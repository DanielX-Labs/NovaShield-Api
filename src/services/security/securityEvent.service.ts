import type { AuthAbuseAssessment } from "./authAbuse.types.js";
import { createHmac } from "node:crypto";
import type { ClientSession, Types } from "mongoose";
import type { Request } from "express";
import { env } from "../../config/env.js";
import { hashIpAddress } from "./networkIdentity.service.js";
import {
  SecurityEventModel,
  type SecurityEventType,
  type SecurityEventSeverity,
} from "../../models/SecurityEvent.model.js";

// Only explicitly selected request attributes may enter permanent audit events.
export interface SecurityContext {
  requestId: string;
  ipHash: string;
  sessionId?: string;
  userAgent?: string;
}

export function hashSecurityIdentifier(value: string): string {
  return createHmac("sha256", env.AUTH_PEPPER)
    .update("security-identifier:")
    .update(value)
    .digest("hex");
}

export function securityContext(req: Request): SecurityContext {
  return {
    requestId: String(req.id),
    ipHash: hashIpAddress(req.ip) ?? "",
  };
}

// No arbitrary metadata argument: passwords, OTPs, and bodies cannot be copied.
export async function recordSecurityEvent(
  eventType: SecurityEventType,
  context: SecurityContext,
  userId?: Types.ObjectId,
  session?: ClientSession,
  severity: SecurityEventSeverity = "INFO",
  abuse?: AuthAbuseAssessment,
): Promise<void> {
  await SecurityEventModel.create([{
    eventType,
    severity,
    // Only fixed assessment fields may enter abuse metadata, never arbitrary bodies.
    ...(abuse ? { metadata: {
      score: abuse.score,
      reasons: abuse.reasons.filter((reason) => [
        "REPEATED_ACCOUNT_FAILURES", "ACCOUNT_FAILURE_THRESHOLD",
        "IP_FAILURE_THRESHOLD", "POSSIBLE_PASSWORD_SPRAY",
        "MULTI_ACCOUNT_FAILURE_PATTERN",
      ].includes(reason)),
      accountFailures: abuse.accountFailures,
      ipFailures: abuse.ipFailures,
      distinctAccountsFromIp: abuse.distinctAccountsFromIp,
    } } : {}),
    // Copy individual allowed fields rather than spreading caller-supplied objects.
    requestId: context.requestId,
    ...(context.ipHash ? { ipHash: context.ipHash } : {}),
    ...(context.sessionId ? { sessionId: context.sessionId } : {}),
    ...(context.userAgent ? { userAgent: context.userAgent.slice(0, 512) } : {}),
    ...(userId ? { userId } : {}),
  }], session ? { session } : {});
}
