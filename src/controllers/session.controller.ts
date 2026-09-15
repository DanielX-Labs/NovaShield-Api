import type { RequestHandler } from "express";
import { z } from "zod";
import {
  listUserSessions, revokeAllUserSessions, revokeUserSession,
} from "../services/session/sessionManagement.service.js";
import { clearRefreshCookie } from "../services/session/refreshCookie.service.js";
import { AppError } from "../utils/AppError.js";

export const listSessionsController: RequestHandler = async (req, res, next) => {
  try {
    if (!req.auth) throw new AppError("Authentication is required.", 401);
    const sessions = await listUserSessions(req.auth.userId);
    // A response allowlist keeps database identifiers and network hashes private.
    res.json({
      success: true,
      data: { sessions: sessions.map((session) => ({
        sessionId: session.sessionId,
        userAgent: session.userAgent,
        lastSeenAt: session.lastSeenAt,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        current: session.sessionId === req.auth!.sessionId,
      })) },
      requestId: req.id,
    });
  } catch (error) { next(error); }
};

export const revokeSessionController: RequestHandler = async (req, res, next) => {
  try {
    if (!req.auth) throw new AppError("Authentication is required.", 401);
    const parsed = z.string().uuid().safeParse(req.params.sessionId);
    if (!parsed.success) {
      throw new AppError("Invalid session identifier.", 400, "VALIDATION_ERROR");
    }
    await revokeUserSession(req.auth.userId, parsed.data, String(req.id));
    // Revoking another device must not erase the current device's cookie.
    if (parsed.data === req.auth.sessionId) clearRefreshCookie(res);
    res.status(204).send();
  } catch (error) { next(error); }
};

export const revokeAllSessionsController: RequestHandler = async (req, res, next) => {
  try {
    if (!req.auth) throw new AppError("Authentication is required.", 401);
    await revokeAllUserSessions(req.auth.userId, String(req.id));
    clearRefreshCookie(res);
    res.status(204).send();
  } catch (error) { next(error); }
};
