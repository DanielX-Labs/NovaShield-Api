import { Types, type ClientSession } from "mongoose";
import {
  AuthAttemptModel, type AuthAttemptOutcome, type AuthAttemptReason,
} from "../../models/AuthAttempt.model.js";
import { env } from "../../config/env.js";
import { hashAuthIdentifier } from "./identifierHash.service.js";
import type { AuthAbuseAssessment, AuthAbuseReason } from "./authAbuse.types.js";

export function calculateProgressiveDelay(failures: number): number {
  if (failures < env.AUTH_PROGRESSIVE_DELAY_AFTER) return 0;
  // Cap the exponent before multiplication, including very large failure counts.
  const exponent = Math.min(failures - env.AUTH_PROGRESSIVE_DELAY_AFTER, 30);
  return Math.min(
    env.AUTH_PROGRESSIVE_DELAY_BASE_MS * 2 ** exponent,
    env.AUTH_PROGRESSIVE_DELAY_MAX_MS,
  );
}

export async function assessLoginAbuse(input: {
  email: string;
  ipHash?: string;
}): Promise<AuthAbuseAssessment> {
  const createdAt = {
    $gte: new Date(Date.now() - env.AUTH_FAILURE_WINDOW_MINUTES * 60_000),
  };
  const ipQuery = { ipHash: input.ipHash ?? "", outcome: "FAILURE" as const, createdAt };
  // Return only a distinct count, rather than transferring every attempted identity.
  const [accountFailures, ipFailures, distinct] = await Promise.all([
    AuthAttemptModel.countDocuments({
      emailHash: hashAuthIdentifier(input.email), outcome: "FAILURE", createdAt,
    }),
    input.ipHash ? AuthAttemptModel.countDocuments(ipQuery) : Promise.resolve(0),
    input.ipHash ? AuthAttemptModel.aggregate<{ count: number }>([
      { $match: ipQuery }, { $group: { _id: "$emailHash" } }, { $count: "count" },
    ]) : Promise.resolve([]),
  ]);
  const distinctAccountsFromIp = distinct[0]?.count ?? 0;
  let score = 0;
  const reasons: AuthAbuseReason[] = [];
  if (accountFailures >= env.AUTH_PROGRESSIVE_DELAY_AFTER) {
    score += 20;
    reasons.push("REPEATED_ACCOUNT_FAILURES");
  }
  if (accountFailures >= env.AUTH_ACCOUNT_FAILURE_LIMIT) {
    score += 40;
    reasons.push("ACCOUNT_FAILURE_THRESHOLD");
  }
  if (ipFailures >= env.AUTH_IP_FAILURE_LIMIT) {
    score += 40;
    reasons.push("IP_FAILURE_THRESHOLD");
  }
  if (distinctAccountsFromIp >= env.AUTH_SPRAY_ACCOUNT_THRESHOLD) {
    score += 50;
    reasons.push("POSSIBLE_PASSWORD_SPRAY");
  }
  if (ipFailures >= 10 && distinctAccountsFromIp >= 5) {
    score += 30;
    reasons.push("MULTI_ACCOUNT_FAILURE_PATTERN");
  }
  // Scores describe indicators, not proof of an attack or an account compromise.
  score = Math.min(score, 100);
  return {
    blocked: accountFailures >= env.AUTH_ACCOUNT_FAILURE_LIMIT
      || ipFailures >= env.AUTH_IP_FAILURE_LIMIT,
    delayMs: calculateProgressiveDelay(accountFailures),
    suspicious: score >= env.AUTH_SUSPICIOUS_SCORE_THRESHOLD,
    score, reasons, accountFailures, ipFailures, distinctAccountsFromIp,
  };
}

export async function recordAuthAttempt(input: {
  email: string;
  ipHash?: string;
  userId?: string;
  outcome: AuthAttemptOutcome;
  reason: AuthAttemptReason;
}, session?: ClientSession): Promise<void> {
  // Select fields explicitly; callers cannot persist a password or arbitrary body.
  await AuthAttemptModel.create([{
    emailHash: hashAuthIdentifier(input.email),
    ...(input.ipHash ? { ipHash: input.ipHash } : {}),
    ...(input.userId ? { userId: new Types.ObjectId(input.userId) } : {}),
    outcome: input.outcome,
    reason: input.reason,
  }], session ? { session } : {});
}
