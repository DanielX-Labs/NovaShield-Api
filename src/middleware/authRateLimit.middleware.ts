import { env } from "../config/env.js";
import { authAbuseLimit } from "./authAbuse.middleware.js";

// Reuse MongoDB counters so login budgets are shared across API processes.
export const loginRateLimit = authAbuseLimit(
  "login-ip",
  env.LOGIN_IP_LIMIT,
  false,
  env.LOGIN_WINDOW_MINUTES * 60_000,
  true,
);
