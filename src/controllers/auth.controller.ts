import type { Request, Response, NextFunction } from "express";
import { loginUser } from "../services/auth/login.service.js";
import { hashIpAddress } from "../services/security/networkIdentity.service.js";
import { setRefreshCookie, clearRefreshCookie } from "../services/session/refreshCookie.service.js";
import { env } from "../config/env.js";
import { AppError } from "../utils/AppError.js";
import { rotateRefreshToken } from "../services/session/refreshToken.service.js";
import { revokeUserSession } from "../services/session/sessionManagement.service.js";

export async function loginController(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const ipHash = hashIpAddress(req.ip);
    const userAgent = req.get("user-agent");
    const result = await loginUser({
      email: req.body.email,
      password: req.body.password,
      requestId: String(req.id),
      ...(userAgent ? { userAgent } : {}),
      ...(ipHash ? { ipHash } : {}),
    });
    setRefreshCookie(res, result.refreshToken);

    // Explicitly allowlist JSON fields: the refresh token belongs only in the cookie.
    res.status(200).json({
      success: true,
      data: {
        userId: result.userId,
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
        sessionId: result.sessionId,
      },
      requestId: req.id,
    });
  } catch (error) {
    next(error);
  }
}

export async function refreshController(
  req: Request, res: Response, next: NextFunction,
): Promise<void> {
  try {
    const rawToken = req.cookies?.[env.REFRESH_COOKIE_NAME];
    if (typeof rawToken !== "string") {
      throw new AppError(
        "The authentication session is invalid or expired.",
        401, "INVALID_REFRESH_TOKEN",
      );
    }
    const ipHash = hashIpAddress(req.ip);
    const userAgent = req.get("user-agent");
    const result = await rotateRefreshToken({
      rawToken,
      requestId: String(req.id),
      ...(ipHash ? { ipHash } : {}),
      ...(userAgent ? { userAgent } : {}),
    });
    setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
    // Refresh secrets never enter JSON, logs, or query-string parameters.
    res.json({
      success: true,
      data: {
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
        sessionId: result.sessionId,
      },
      requestId: req.id,
    });
  } catch (error) {
    // Keep the cookie on transient outages so clients can retry an unused token.
    if (error instanceof AppError && error.statusCode === 401) {
      clearRefreshCookie(res);
    }
    next(error);
  }
}

export async function logoutController(
  req: Request, res: Response, next: NextFunction,
): Promise<void> {
  try {
    if (!req.auth) throw new AppError("Authentication is required.", 401);
    // Server-side revocation must commit before acknowledging logout.
    await revokeUserSession(req.auth.userId, req.auth.sessionId, String(req.id));
    clearRefreshCookie(res);
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}
