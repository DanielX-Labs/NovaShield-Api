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
import { enqueueEmail } from "../email/emailOutbox.service.js";

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
  // Queue the notification atomically, before committing the credential change.
  await enqueueEmail({ userId: user._id, email, kind: "PASSWORD_CHANGED", requestId,
    expiresAt: new Date(Date.now() + 7 * 86400_000) }, transaction);
}
