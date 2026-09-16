import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { AbuseBucketModel } from "../../models/AbuseBucket.model.js";
import { normalizeEmail } from "../../utils/email.js";
import { env } from "../../config/env.js";
import { AppError } from "../../utils/AppError.js";
import { createOtpChallenge, verifyOtpChallenge } from "../otp/otpChallenge.service.js";
import { enqueueEmail } from "../email/emailOutbox.service.js";
import { recordSecurityEvent } from "../security/securityEvent.service.js";
import { sessionTransaction } from "../session/sessionTransaction.js";
import {
  prepareReplacement, replaceCredential,
} from "./passwordLifecycle.service.js";

function invalidReset(): AppError {
  return new AppError(
    "The password reset code is invalid or expired.", 400, "PASSWORD_RESET_INVALID",
  );
}

export async function requestPasswordReset(input: {
  email: string; requestId?: string;
}): Promise<void> {
  const email = normalizeEmail(input.email);
  const context = { requestId: input.requestId ?? "", ipHash: "" };
  await sessionTransaction(async (transaction) => {
    // This shared cooldown prevents concurrent requests from issuing multiple codes.
    const user = await AuthUserModel.findOneAndUpdate({
      emailNormalized: email, status: "ACTIVE", isEmailVerified: true,
      $or: [
        { passwordResetOtpIssuedAt: { $exists: false } },
        { passwordResetOtpIssuedAt: {
          $lte: new Date(Date.now() - env.OTP_RESEND_COOLDOWN_SECONDS * 1000),
        } },
      ],
    }, { $set: { passwordResetOtpIssuedAt: new Date() } }, {
      returnDocument: "after", session: transaction,
    });
    if (!user) return null;
    const credential = await CredentialModel.findOne({ userId: user._id })
      .session(transaction);
    if (!credential) return null;
    // Anonymous requests must not replace a usable code already in the owner's inbox.
    const outstanding = await OtpChallengeModel.exists({
      userId: user._id, purpose: "PASSWORD_RESET", credentialVersion: credential.passwordVersion,
      resetProtocolVersion: 2,
      consumedAt: { $exists: false }, expiresAt: { $gt: new Date() },
      $expr: { $lt: ["$attempts", "$maxAttempts"] },
    }).session(transaction);
    if (outstanding) return null;
    // Count actual issuance while the user write serializes competing requests.
    const windowMs = env.PASSWORD_RESET_REQUEST_WINDOW_MINUTES * 60_000;
    const window = Math.floor(Date.now() / windowMs);
    const bucketId = `reset-issued:${user._id.toHexString()}:${window}`;
    const bucket = await AbuseBucketModel.findById(bucketId).session(transaction);
    if (bucket && bucket.count >= env.PASSWORD_RESET_REQUEST_LIMIT) return null;
    await AbuseBucketModel.updateOne({ _id: bucketId }, {
      $inc: { count: 1 },
      $setOnInsert: { expiresAt: new Date((window + 2) * windowMs) },
    }, { upsert: true, session: transaction });
    const challenge = await createOtpChallenge({
      userId: user._id,
      purpose: "PASSWORD_RESET",
      target: email,
      ttlMinutes: env.PASSWORD_RESET_OTP_TTL_MINUTES,
      maxAttempts: env.PASSWORD_RESET_MAX_ATTEMPTS,
      credentialVersion: credential.passwordVersion,
    }, transaction);
    await recordSecurityEvent(
      "AUTH_PASSWORD_RESET_REQUESTED", context, user._id, transaction, "LOW",
    );
    await enqueueEmail({ userId: user._id, ...challenge, email, kind: "RESET",
      expiresAt: new Date(Date.now() + env.PASSWORD_RESET_OTP_TTL_MINUTES * 60_000),
      requestId: context.requestId }, transaction);
  });
}

export async function confirmPasswordReset(input: {
  email: string; challengeId: string; otp: string; newPassword: string; requestId?: string;
}): Promise<void> {
  if (!/^[a-f0-9]{24}$/u.test(input.challengeId)) throw invalidReset();
  const email = normalizeEmail(input.email);
  const user = await AuthUserModel.findOne({ emailNormalized: email });
  if (!user || !user.isEmailVerified || user.status !== "ACTIVE") throw invalidReset();
  const credential = await CredentialModel.findOne({ userId: user._id })
    .select("+passwordHash");
  if (!credential) throw invalidReset();
  const requestId = input.requestId ?? "";

  // Prove knowledge before exposing account-specific history or current-password
  // feedback. This reserves an attempt but does not consume the OTP.
  const proof = await verifyOtpChallenge(
    user._id, "PASSWORD_RESET", input.otp, email, { requestId, ipHash: "" },
    input.challengeId,
  );
  if (!proof || proof.credentialVersion !== credential.passwordVersion) throw invalidReset();
  const newHash = await prepareReplacement(credential, input.newPassword, email);

  await sessionTransaction(async (transaction) => {
    // The exact challenge is rechecked after policy/Argon2 work; stale proofs fail.
    const consumed = await OtpChallengeModel.findOneAndUpdate({
      _id: proof.challengeId,
      userId: user._id,
      purpose: "PASSWORD_RESET",
      target: email,
      credentialVersion: credential.passwordVersion,
      resetProtocolVersion: 2,
      consumedAt: { $exists: false },
      expiresAt: { $gt: new Date() },
    }, { $set: { consumedAt: new Date() } }, {
      returnDocument: "after", session: transaction,
    });
    if (!consumed) throw invalidReset();
    await replaceCredential(
      credential, newHash, email,
      "AUTH_PASSWORD_RESET_COMPLETED", requestId, transaction,
    );
  });
}
