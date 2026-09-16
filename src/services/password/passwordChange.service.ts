import { Types } from "mongoose";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { SessionModel } from "../../models/Session.model.js";
import { AppError } from "../../utils/AppError.js";
import { verifyPassword } from "./passwordHash.service.js";
import {
  prepareReplacement, replaceCredential,
} from "./passwordLifecycle.service.js";
import { sessionTransaction } from "../session/sessionTransaction.js";

interface ChangePasswordInput {
  userId: string;
  sessionId: string;
  passwordVersion: number;
  currentPassword: string;
  newPassword: string;
  requestId?: string;
}

export async function changePassword(input: ChangePasswordInput): Promise<void> {
  const userId = new Types.ObjectId(input.userId);
  const [user, credential] = await Promise.all([
    AuthUserModel.findById(userId),
    CredentialModel.findOne({ userId }).select("+passwordHash"),
  ]);
  if (!user || !credential || !user.isEmailVerified || user.status !== "ACTIVE"
    || credential.passwordVersion !== input.passwordVersion) {
    throw new AppError("Authentication is invalid.", 401, "AUTHENTICATION_REQUIRED");
  }
  if (!await verifyPassword(credential.passwordHash, input.currentPassword)) {
    throw new AppError("Current password is incorrect.", 400, "CURRENT_PASSWORD_INVALID");
  }
  const newHash = await prepareReplacement(
    credential, input.newPassword, user.emailNormalized,
  );
  const requestId = input.requestId ?? "";

  await sessionTransaction(async (transaction) => {
    // Recheck the authenticating session after potentially slow password screening.
    const validSession = await SessionModel.exists({
      userId,
      sessionId: input.sessionId,
      passwordVersion: input.passwordVersion,
      revokedAt: { $exists: false },
      expiresAt: { $gt: new Date() },
    }).session(transaction);
    if (!validSession) {
      throw new AppError("Authentication is invalid.", 401, "AUTHENTICATION_REQUIRED");
    }
    await replaceCredential(
      credential, newHash, user.emailNormalized,
      "AUTH_PASSWORD_CHANGED", requestId, transaction,
    );
  });
}
