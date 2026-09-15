import type { RequestHandler } from "express";
import { Types } from "mongoose";
import { verifyAccessToken } from "../services/session/accessToken.service.js";
import { SessionModel } from "../models/Session.model.js";
import { CredentialModel } from "../models/Credential.model.js";
import { AuthUserModel } from "../models/AuthUser.model.js";
import { AppError } from "../utils/AppError.js";

export const authenticate: RequestHandler = async (req, _res, next) => {
  const authorization = req.get("authorization");
  if (!authorization?.startsWith("Bearer ")) {
    next(new AppError("Authentication is required.", 401, "AUTHENTICATION_REQUIRED"));
    return;
  }
  let payload;
  try {
    payload = verifyAccessToken(authorization.slice(7));
    if (!/^[a-f0-9]{24}$/u.test(payload.sub)) throw new Error("Invalid subject.");
  } catch {
    next(new AppError(
      "Authentication is invalid or expired.", 401, "INVALID_ACCESS_TOKEN",
    ));
    return;
  }

  try {
    const userId = new Types.ObjectId(payload.sub);
    // Read authoritative state on every request so revoked JWTs stop working now.
    const [user, session, credential] = await Promise.all([
      AuthUserModel.findById(userId),
      SessionModel.findOne({ userId, sessionId: payload.sid }),
      CredentialModel.findOne({ userId }),
    ]);
    if (!user || !session || !credential
      || !user.isEmailVerified || user.status !== "ACTIVE"
      || session.revokedAt || session.expiresAt <= new Date()
      || credential.passwordVersion !== payload.ver
      || session.passwordVersion !== payload.ver) {
      next(new AppError(
        "Authentication is invalid or expired.", 401, "INVALID_ACCESS_TOKEN",
      ));
      return;
    }
    req.auth = {
      userId: userId.toHexString(),
      sessionId: session.sessionId,
      passwordVersion: credential.passwordVersion,
    };
    next();
  } catch {
    // An outage is a 503, not a misleading bad-token response; access stays denied.
    next(new AppError("Authentication is temporarily unavailable.", 503, "AUTH_UNAVAILABLE"));
  }
};
