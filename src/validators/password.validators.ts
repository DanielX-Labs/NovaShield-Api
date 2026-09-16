import { z } from "zod";
import { env } from "../config/env.js";

// Preserve password bytes; normalize only the email identity.
const password = z.string().min(1).max(env.PASSWORD_MAX_LENGTH);
const email = z.string().trim().email().max(254).toLowerCase();

export const changePasswordSchema = z.object({
  body: z.object({ currentPassword: password, newPassword: password }).strict(),
});
export const passwordResetRequestSchema = z.object({
  body: z.object({ email }).strict(),
});
export const passwordResetConfirmSchema = z.object({
  body: z.object({
    email,
    // Delivered only through the mailbox, never returned by reset request.
    challengeId: z.string().regex(/^[a-f0-9]{24}$/u),
    otp: z.string().regex(/^\d{6}$/u),
    newPassword: password,
  }).strict(),
});
