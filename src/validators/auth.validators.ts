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
