import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { normalizeEmail } from "../../utils/email.js";
import { env } from "../../config/env.js";
import { AppError } from "../../utils/AppError.js";
import { logger } from "../../config/logger.js";
import { createOtpChallenge, verifyOtpChallenge } from "../otp/otpChallenge.service.js";
import { sendPasswordResetOtpEmail } from "../email/email.service.js";
import { recordSecurityEvent } from "../security/securityEvent.service.js";
import { sessionTransaction } from "../session/sessionTransaction.js";
import {
  prepareReplacement, replaceCredential, notifyPasswordChanged,
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
  const result = await sessionTransaction(async (transaction) => {
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
    return { userId: user._id, ...challenge };
  });
  if (!result) return;

  try {
    // Never send email inside a transaction callback that may be retried.
    await sendPasswordResetOtpEmail(email, result.otp);
  } catch {
    // SMTP failure must not reveal whether an eligible account exists.
    try {
      await sessionTransaction(async (transaction) => {
        await OtpChallengeModel.updateOne({ _id: result.challengeId }, {
          $set: { consumedAt: new Date() },
        }, { session: transaction });
        await recordSecurityEvent(
          "AUTH_EMAIL_DELIVERY_FAILURE", context, result.userId, transaction, "LOW",
        );
      });
    } catch {
      logger.warn({ requestId: context.requestId }, "Reset delivery recovery failed.");
    }
  }
}

export async function confirmPasswordReset(input: {
  email: string; otp: string; newPassword: string; requestId?: string;
}): Promise<void> {
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
  await notifyPasswordChanged(user._id, email, requestId);
}
