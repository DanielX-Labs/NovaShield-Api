import { timingSafeEqual } from "node:crypto";
import { Types } from "mongoose";
import { RefreshTokenModel } from "../../models/RefreshToken.model.js";
import { SessionModel } from "../../models/Session.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { env } from "../../config/env.js";
import { AppError } from "../../utils/AppError.js";
import {
  generateRefreshToken, hashRefreshToken, parseRefreshToken,
} from "./refreshTokenCrypto.service.js";
import { createAccessToken } from "./accessToken.service.js";
import { recordSecurityEvent } from "../security/securityEvent.service.js";
import { revokeSessionRecords } from "./sessionManagement.service.js";
import { sessionTransaction } from "./sessionTransaction.js";

interface RotateRefreshTokenInput {
  rawToken: string;
  requestId?: string;
  userAgent?: string;
  ipHash?: string;
}

function invalidRefresh(code = "INVALID_REFRESH_TOKEN"): AppError {
  return new AppError(
    "The authentication session is invalid or expired.", 401, code,
  );
}

export async function rotateRefreshToken(input: RotateRefreshTokenInput) {
  const parsed = parseRefreshToken(input.rawToken);
  if (!parsed) throw invalidRefresh();
  const suppliedHash = hashRefreshToken(input.rawToken);

  const outcome = await sessionTransaction(async (transaction) => {
    const stored = await RefreshTokenModel.findById(parsed.tokenId)
      .select("+tokenHash +usedAt +revokedAt")
      .session(transaction);
    // Authenticate the whole secret before any reuse-triggered revocation.
    if (!stored || !/^[a-f0-9]{64}$/u.test(stored.tokenHash)
      || !timingSafeEqual(
        Buffer.from(stored.tokenHash, "hex"),
        Buffer.from(suppliedHash, "hex"),
      )) return { error: "INVALID_REFRESH_TOKEN" };

    const session = await SessionModel.findOne({
      _id: stored.sessionId, userId: stored.userId,
    }).session(transaction);
    if (!session) return { error: "INVALID_SESSION" };
    const context = {
      requestId: input.requestId ?? "",
      ipHash: input.ipHash ?? "",
      sessionId: session.sessionId,
      ...(input.userAgent ? { userAgent: input.userAgent.slice(0, 512) } : {}),
    };

    if (stored.usedAt) {
      await revokeSessionRecords(
        stored.userId, session._id, "REFRESH_TOKEN_REUSE", transaction,
      );
      // Commit revocation and its audit before returning the public rejection.
      // Avoid duplicate audit entries for repeated requests after revocation.
      if (!session.revokedAt) {
        await recordSecurityEvent(
          "AUTH_REFRESH_REUSED", context, stored.userId, transaction, "HIGH",
        );
      }
      return { error: "REFRESH_TOKEN_REUSED" };
    }

    const now = new Date();
    if (stored.revokedAt) return { error: "INVALID_REFRESH_TOKEN" };
    if (stored.expiresAt <= now) return { error: "REFRESH_TOKEN_EXPIRED" };
    if (session.revokedAt || session.expiresAt <= now) {
      return { error: "INVALID_SESSION" };
    }

    const user = await AuthUserModel.findById(stored.userId).session(transaction);
    const credential = await CredentialModel.findOne({
      userId: stored.userId,
    }).session(transaction);
    if (!user || !user.isEmailVerified || user.status !== "ACTIVE"
      || !credential || session.passwordVersion !== credential.passwordVersion) {
      await revokeSessionRecords(
        stored.userId, session._id, "ACCOUNT_OR_CREDENTIAL_CHANGED", transaction,
      );
      await recordSecurityEvent(
        "AUTH_SESSION_REVOKED", context, stored.userId, transaction,
      );
      return { error: "INVALID_SESSION" };
    }

    const replacement = generateRefreshToken();
    const replacementId = new Types.ObjectId(replacement.tokenId);
    // Atomic consumption inside the transaction admits only one winning rotation.
    const consumed = await RefreshTokenModel.findOneAndUpdate({
      _id: stored._id,
      usedAt: { $exists: false },
      revokedAt: { $exists: false },
    }, {
      $set: { usedAt: now, replacedByTokenId: replacementId },
    }, { returnDocument: "after", session: transaction });
    if (!consumed) {
      await revokeSessionRecords(
        stored.userId, session._id, "CONCURRENT_REFRESH_OR_REUSE", transaction,
      );
      await recordSecurityEvent(
        "AUTH_REFRESH_REUSED", context, stored.userId, transaction, "HIGH",
      );
      return { error: "REFRESH_TOKEN_REUSED" };
    }

    // Session writes serialize rotation against logout and revoke-all operations.
    await SessionModel.updateOne(
      { _id: session._id },
      { $set: { lastSeenAt: now } },
      { session: transaction },
    );
    const expiresAt = new Date(Math.min(
      stored.expiresAt.getTime(), session.expiresAt.getTime(),
    ));
    await RefreshTokenModel.create([{
      _id: replacementId,
      userId: stored.userId,
      sessionId: stored.sessionId,
      familyId: stored.familyId,
      tokenHash: hashRefreshToken(replacement.rawToken),
      expiresAt,
    }], { session: transaction });
    await recordSecurityEvent(
      "AUTH_REFRESH_ROTATED", context, stored.userId, transaction,
    );
    return {
      accessToken: createAccessToken({
        sub: stored.userId.toHexString(),
        sid: session.sessionId,
        type: "access",
        ver: credential.passwordVersion,
      }),
      refreshToken: replacement.rawToken,
      expiresIn: env.ACCESS_TOKEN_TTL_MINUTES * 60,
      sessionId: session.sessionId,
      refreshExpiresAt: expiresAt,
    };
  });

  // Throw only outside the transaction, otherwise replay revocation would roll back.
  if ("error" in outcome) throw invalidRefresh(outcome.error);
  return outcome;
}
