import { randomUUID } from "node:crypto";
import mongoose, { Types, type ClientSession } from "mongoose";
import { env } from "../../config/env.js";
import { SessionModel } from "../../models/Session.model.js";
import { RefreshTokenModel } from "../../models/RefreshToken.model.js";
import { createAccessToken } from "./accessToken.service.js";
import {
  generateRefreshToken,
  hashRefreshToken,
} from "./refreshTokenCrypto.service.js";

interface CreateSessionInput {
  userId: Types.ObjectId;
  passwordVersion: number;
  userAgent?: string;
  ipHash?: string;
}

// Login passes its transaction so session, refresh token, and audit commit together.
export async function createSession(
  input: CreateSessionInput,
  transaction?: ClientSession,
): Promise<{
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  sessionId: string;
}> {
  if (!transaction) {
    return mongoose.connection.transaction((session) => createSession(input, session));
  }

  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
  );
  const sessionObjectId = new Types.ObjectId();
  const publicSessionId = randomUUID();
  const familyId = randomUUID();
  const refresh = generateRefreshToken();

  await SessionModel.create([{
    _id: sessionObjectId,
    userId: input.userId,
    sessionId: publicSessionId,
    ...(input.userAgent ? { userAgent: input.userAgent.slice(0, 512) } : {}),
    ...(input.ipHash ? { ipHash: input.ipHash } : {}),
    lastSeenAt: now,
    expiresAt,
  }], { session: transaction });

  // Preserve the family ID for future rotation; raw tokens never reach MongoDB.
  await RefreshTokenModel.create([{
    _id: new Types.ObjectId(refresh.tokenId),
    userId: input.userId,
    sessionId: sessionObjectId,
    familyId,
    tokenHash: hashRefreshToken(refresh.rawToken),
    expiresAt,
  }], { session: transaction });

  const accessToken = createAccessToken({
    sub: input.userId.toHexString(),
    sid: publicSessionId,
    type: "access",
    ver: input.passwordVersion,
  });
  return {
    accessToken,
    refreshToken: refresh.rawToken,
    expiresIn: env.ACCESS_TOKEN_TTL_MINUTES * 60,
    sessionId: publicSessionId,
  };
}
