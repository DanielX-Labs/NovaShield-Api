import { Types, type ClientSession } from "mongoose";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { AppError } from "../../utils/AppError.js";
import { addPasswordToHistory } from "./passwordHistory.service.js";
import { validatePasswordChange } from "./password.service.js";
import { hashPassword, verifyPassword } from "./passwordHash.service.js";
import { revokeAllUserSessions } from "../session/sessionManagement.service.js";
import { recordSecurityEvent } from "../security/securityEvent.service.js";
import { sendPasswordChangedEmail } from "../email/email.service.js";
import { logger } from "../../config/logger.js";

export interface CredentialSnapshot {
  userId: Types.ObjectId;
  passwordHash: string;
  passwordVersion: number;
}

// Do expensive policy, breach, history and Argon2 work outside retryable transactions.
export async function prepareReplacement(
  credential: CredentialSnapshot,
  newPassword: string,
  email: string,
): Promise<string> {
  if (await verifyPassword(credential.passwordHash, newPassword)) {
    throw new AppError(
      "Choose a password that has not been used recently.",
      400, "PASSWORD_RECENTLY_USED",
    );
  }
  await validatePasswordChange(credential.userId, newPassword, { email });
  return hashPassword(newPassword);
}

export async function replaceCredential(
  credential: CredentialSnapshot,
  newHash: string,
  email: string,
  eventType: "AUTH_PASSWORD_CHANGED" | "AUTH_PASSWORD_RESET_COMPLETED",
  requestId: string,
  transaction: ClientSession,
): Promise<void> {
  const now = new Date();
  // Compare-and-swap rejects a password that changed while security checks ran.
  const updated = await CredentialModel.updateOne({
    userId: credential.userId,
    passwordHash: credential.passwordHash,
    passwordVersion: credential.passwordVersion,
  }, {
    $set: { passwordHash: newHash, lastChangedAt: now },
    $inc: { passwordVersion: 1 },
  }, { session: transaction });
  if (updated.modifiedCount !== 1) {
    throw new AppError(
      "Authentication changed. Please try again.", 409, "PASSWORD_STATE_CHANGED",
    );
  }

  // Lock the identity as well, serializing with login and reset issuance.
  const user = await AuthUserModel.findOneAndUpdate({
    _id: credential.userId,
    emailNormalized: email,
    status: "ACTIVE",
    isEmailVerified: true,
  }, { $set: { passwordChangedAt: now } }, {
    returnDocument: "after", session: transaction,
  });
  if (!user) {
    throw new AppError("Authentication is invalid.", 401, "AUTHENTICATION_REQUIRED");
  }

  // History contains prior credentials, never the newly current hash.
  await addPasswordToHistory(credential.userId, credential.passwordHash, transaction);
  await OtpChallengeModel.updateMany({
    userId: credential.userId,
    consumedAt: { $exists: false },
  }, { $set: { consumedAt: now } }, { session: transaction });
  await revokeAllUserSessions(user._id.toHexString(), requestId, transaction);
  await recordSecurityEvent(
    eventType, { requestId, ipHash: "" }, user._id, transaction, "MEDIUM",
  );
}

export async function notifyPasswordChanged(
  userId: Types.ObjectId,
  email: string,
  requestId: string,
): Promise<void> {
  try {
    // The security transaction has already committed before delivery is attempted.
    await sendPasswordChangedEmail(email);
  } catch {
    try {
      await recordSecurityEvent(
        "AUTH_SECURITY_NOTIFICATION_FAILURE",
        { requestId, ipHash: "" },
        userId, undefined, "LOW",
      );
    } catch {
      // Even audit unavailability must not turn a completed change into a failure.
      logger.warn({ requestId }, "Password notification could not be recorded.");
    }
  }
}
