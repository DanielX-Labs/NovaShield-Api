import type { Request, Response, NextFunction } from "express";
import { loginUser } from "../services/auth/login.service.js";
import { hashIpAddress } from "../services/security/networkIdentity.service.js";
import { setRefreshCookie } from "../services/session/refreshCookie.service.js";

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
