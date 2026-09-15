import type { Request, Response } from "express";
import { AppError } from "../utils/AppError.js";
import { changePassword } from "../services/password/passwordChange.service.js";
import {
  requestPasswordReset,
  confirmPasswordReset,
} from "../services/password/passwordReset.service.js";
import { clearRefreshCookie } from "../services/session/refreshCookie.service.js";

export async function changePasswordController(
  req: Request,
  res: Response,
): Promise<void> {
  // Identity comes exclusively from the authenticated session, never the body.
  if (!req.auth) {
    throw new AppError("Authentication is required.", 401, "AUTHENTICATION_REQUIRED");
  }
  await changePassword({ ...req.body, ...req.auth, requestId: String(req.id) });
  clearRefreshCookie(res);
  res.status(200).json({
    success: true,
    message: "Password changed. Please sign in again.",
    requestId: String(req.id),
  });
}

export async function passwordResetRequestController(
  req: Request,
  res: Response,
): Promise<void> {
  await requestPasswordReset({ email: req.body.email, requestId: String(req.id) });
  // Unknown, ineligible and cooldown requests receive the same public response.
  res.status(202).json({
    success: true,
    message: "If eligible, a password reset code will be sent to this address.",
    requestId: String(req.id),
  });
}

export async function passwordResetConfirmController(
  req: Request,
  res: Response,
): Promise<void> {
  await confirmPasswordReset({ ...req.body, requestId: String(req.id) });
  // Clear the browser credential only after the security transaction commits.
  clearRefreshCookie(res);
  res.status(200).json({
    success: true,
    message: "Password reset. Please sign in again.",
    requestId: String(req.id),
  });
}
