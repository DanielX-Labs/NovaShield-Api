import { Types, type ClientSession } from "mongoose";
import { SessionModel } from "../../models/Session.model.js";
import { RefreshTokenModel } from "../../models/RefreshToken.model.js";
import { AppError } from "../../utils/AppError.js";
import {
  recordSecurityEvent,
  type SecurityContext,
} from "../security/securityEvent.service.js";
import { sessionTransaction } from "./sessionTransaction.js";

// Shared by replay handling, logout, and explicit revocation within a transaction.
export async function revokeSessionRecords(
  userId: Types.ObjectId,
  sessionObjectId: Types.ObjectId,
  reason: string,
  transaction: ClientSession,
): Promise<void> {
  const now = new Date();
  await SessionModel.updateOne({
    _id: sessionObjectId, userId, revokedAt: { $exists: false },
  }, {
    $set: { revokedAt: now, revokeReason: reason },
  }, { session: transaction });
  // Revoke every family bound to this session; no replacement can escape the lock.
  await RefreshTokenModel.updateMany({
    userId, sessionId: sessionObjectId, revokedAt: { $exists: false },
  }, { $set: { revokedAt: now } }, { session: transaction });
}

export async function listUserSessions(userId: string) {
  // Explicit projection excludes internal IDs and network identifiers.
  return SessionModel.find({
    userId: new Types.ObjectId(userId),
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  })
    .sort({ lastSeenAt: -1 })
    .select("-_id sessionId userAgent lastSeenAt expiresAt createdAt")
    .lean();
}

export async function revokeUserSession(
  userId: string,
  sessionId: string,
  requestId?: string,
): Promise<void> {
  await sessionTransaction(async (transaction) => {
    const userObjectId = new Types.ObjectId(userId);
    // Ownership is part of the query, never a later authorization check.
    const session = await SessionModel.findOne({
      userId: userObjectId, sessionId,
    }).session(transaction);
    if (!session) {
      throw new AppError("Session was not found.", 404, "SESSION_NOT_FOUND");
    }
    await revokeSessionRecords(userObjectId, session._id, "USER_REVOKED", transaction);
    if (!session.revokedAt) {
      await recordSecurityEvent(
        "AUTH_SESSION_REVOKED",
        { requestId: requestId ?? "", ipHash: "", sessionId },
        userObjectId,
        transaction,
      );
    }
  });
}

export async function revokeAllUserSessions(
  userId: string,
  requestId?: string,
  transaction?: ClientSession,
): Promise<void> {
  // Reuse the caller's transaction so password replacement and revocation are atomic.
  if (!transaction) {
    return sessionTransaction((session) =>
      revokeAllUserSessions(userId, requestId, session),
    );
  }
  const userObjectId = new Types.ObjectId(userId);
  const now = new Date();
  // Updating session documents conflicts with concurrent refresh writes.
  await SessionModel.updateMany({
    userId: userObjectId, revokedAt: { $exists: false },
  }, {
    $set: { revokedAt: now, revokeReason: "USER_REVOKED_ALL" },
  }, { session: transaction });
  await RefreshTokenModel.updateMany({
    userId: userObjectId, revokedAt: { $exists: false },
  }, { $set: { revokedAt: now } }, { session: transaction });
  const context: SecurityContext = { requestId: requestId ?? "", ipHash: "" };
  await recordSecurityEvent(
    "AUTH_SESSION_REVOKED", context, userObjectId, transaction,
  );
}
