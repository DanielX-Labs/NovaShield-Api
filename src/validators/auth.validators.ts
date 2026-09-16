import { z } from "zod";
import { env } from "../config/env.js";

// Preserve password whitespace and casing; login does not reapply creation policy.
export const loginSchema = z.object({
  body: z.object({
    email: z.string().trim().email().max(254).toLowerCase(),
    password: z.string().min(1).max(env.PASSWORD_MAX_LENGTH),
  }).strict(),
});

export type LoginInput = z.infer<typeof loginSchema>["body"];

// Shared strict validation keeps identity normalization consistent across routes.
const emailSchema = z.string().trim().max(254).email().toLowerCase();
export const registrationSchema = z.object({ body: z.object({
  email: emailSchema,
  password: z.string().min(1).max(env.PASSWORD_MAX_LENGTH),
  name: z.string().trim().min(1).max(100).optional(),
}).strict() });
export const resendSchema = z.object({ body: z.object({ email: emailSchema }).strict() });
export const verificationSchema = z.object({ body: z.object({
  challengeId: z.string().regex(/^[a-f0-9]{24}$/u),
  otp: z.string().regex(/^\d{6}$/u),
  // Final credential selection belongs to the mailbox owner proving this challenge.
  password: z.string().min(1).max(env.PASSWORD_MAX_LENGTH),
}).strict() });
