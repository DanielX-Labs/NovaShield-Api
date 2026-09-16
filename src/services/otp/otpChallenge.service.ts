import { Types, type ClientSession } from "mongoose";
import { randomBytes } from "node:crypto";
import { env } from "../../config/env.js";
import {
  OtpChallengeModel, type OtpPurpose,
} from "../../models/OtpChallenge.model.js";
import { generateOtp, hashOtp, verifyOtpHash } from "./otp.service.js";
import { sessionTransaction } from "../session/sessionTransaction.js";
import {
  recordSecurityEvent, type SecurityContext,
} from "../security/securityEvent.service.js";

interface CreateChallengeInput {
  userId: Types.ObjectId;
  purpose: OtpPurpose;
  target: string;
  ttlMinutes?: number;
  maxAttempts?: number;
  credentialVersion?: number;
  challengeId?: Types.ObjectId;
  otp?: string;
}

// Callers serialize issuance through the user document before invoking this helper.
export async function createOtpChallenge(
  input: CreateChallengeInput,
  transaction: ClientSession,
) {
  // Reset challenge locators must not expose ObjectId timestamp/counter sequences.
  const challengeId = input.challengeId ?? new Types.ObjectId(randomBytes(12));
  const otp = input.otp ?? generateOtp();
  const now = new Date();
  await OtpChallengeModel.updateMany({
    userId: input.userId,
    purpose: input.purpose,
    consumedAt: { $exists: false },
  }, { $set: { consumedAt: now } }, { session: transaction });
  await OtpChallengeModel.create([{
    _id: challengeId,
    userId: input.userId,
    purpose: input.purpose,
    target: input.target,
    ...(input.purpose === "PASSWORD_RESET" ? { resetProtocolVersion: 2 } : {}),
    ...(input.purpose === "EMAIL_VERIFICATION" ? { verificationProtocolVersion: 2 } : {}),
    otpHash: hashOtp(otp, challengeId.toHexString()),
    expiresAt: new Date(
      now.getTime() + (input.ttlMinutes ?? env.OTP_TTL_MINUTES) * 60_000,
    ),
    maxAttempts: input.maxAttempts ?? env.OTP_MAX_ATTEMPTS,
    ...(input.credentialVersion ? { credentialVersion: input.credentialVersion } : {}),
  }], { session: transaction });
  return { challengeId, otp };
}

// Reserve an attempt and prove knowledge without consuming the challenge yet.
// The password update later rechecks and consumes this exact challenge atomically.
export async function verifyOtpChallenge(
  userId: Types.ObjectId,
  purpose: "PASSWORD_RESET",
  otp: string,
  target: string,
  context: SecurityContext,
  challengeId: string,
) {
  return sessionTransaction(async (transaction) => {
    const challenge = await OtpChallengeModel.findOneAndUpdate({
      _id: challengeId, userId, purpose, target, resetProtocolVersion: 2,
      consumedAt: { $exists: false },
      expiresAt: { $gt: new Date() },
      $expr: { $lt: ["$attempts", "$maxAttempts"] },
    }, { $inc: { attempts: 1 } }, {
      sort: { createdAt: -1, _id: -1 },
      returnDocument: "after",
      session: transaction,
    }).select("+otpHash +credentialVersion");
    if (!challenge) return null;
    if (!verifyOtpHash(otp, challenge._id.toHexString(), challenge.otpHash)) {
      await recordSecurityEvent(
        "AUTH_PASSWORD_RESET_OTP_FAILURE", context, userId, transaction, "LOW",
      );
      // Returning commits the failed attempt; throwing here would roll it back.
      return null;
    }
    return {
      challengeId: challenge._id,
      credentialVersion: challenge.credentialVersion,
    };
  });
}
