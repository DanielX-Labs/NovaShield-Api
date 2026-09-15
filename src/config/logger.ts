import pino from "pino";
import { env } from "./env.js";

export const logger = pino({
  name: env.APP_NAME,
  level: env.NODE_ENV === "production" ? "info" : "debug",
  // Defense in depth if sensitive fields are passed to structured logging.
  redact: {
    paths: [
      "password", "newPassword", "currentPassword", "confirmPassword",
      "otp", "token", "accessToken", "refreshToken", "authorization",
      "req.headers.authorization", "req.headers.cookie",
      "req.body.password", "req.body.newPassword", "req.body.currentPassword",
      "req.body.confirmPassword", "req.body.otp", "req.body.token",
      "req.body.accessToken", "req.body.refreshToken", "res.headers.set-cookie",
    ],
    censor: "[REDACTED]",
  },
});
