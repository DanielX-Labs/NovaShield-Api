import type { CookieOptions, Response } from "express";
import { env } from "../../config/env.js";

// Use the same scope on set and clear; omit Domain to keep the cookie host-only.
function options(): CookieOptions {
  return {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: env.COOKIE_SAME_SITE,
    path: "/api/v1/auth",
  };
}

export function setRefreshCookie(
  res: Response,
  refreshToken: string,
  expiresAt?: Date,
): void {
  res.cookie(env.REFRESH_COOKIE_NAME, refreshToken, {
    ...options(),
    // Rotation preserves the family's absolute lifetime, including in the browser.
    maxAge: expiresAt
      ? Math.max(0, expiresAt.getTime() - Date.now())
      : env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
  });
}

// Delete with the same attributes used when setting the cookie.
export function clearRefreshCookie(res: Response): void {
  res.clearCookie(env.REFRESH_COOKIE_NAME, options());
}
