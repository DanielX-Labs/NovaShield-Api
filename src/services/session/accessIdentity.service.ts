import { Types } from "mongoose";
import { verifyAccessToken } from "./accessToken.service.js";
import { SessionModel } from "../../models/Session.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { AppError } from "../../utils/AppError.js";

// One authoritative check serves both local routes and authenticated introspection.
export async function resolveAccessIdentity(token: string) {
  let payload;
  try {
    payload = verifyAccessToken(token);
    if (!/^[a-f0-9]{24}$/u.test(payload.sub)) return null;
  } catch {
    return null;
  }

  try {
    const userId = new Types.ObjectId(payload.sub);
    const [user, session, credential] = await Promise.all([
      AuthUserModel.findById(userId),
      SessionModel.findOne({ userId, sessionId: payload.sid }),
      CredentialModel.findOne({ userId }),
    ]);
    if (!user || !session || !credential
      || !user.isEmailVerified || user.status !== "ACTIVE"
      || session.revokedAt || session.expiresAt <= new Date()
      || credential.passwordVersion !== payload.ver
      || session.passwordVersion !== payload.ver) return null;

    return {
      userId: userId.toHexString(),
      sessionId: session.sessionId,
      passwordVersion: credential.passwordVersion,
    };
  } catch {
    // Storage outages are retryable failures, never proof that a token is active.
    throw new AppError("Authentication is temporarily unavailable.", 503, "AUTH_UNAVAILABLE");
  }
}
