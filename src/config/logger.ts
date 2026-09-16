import pino, { type DestinationStream } from "pino";
import { env } from "./env.js";
import { safeErrorDetails, safeOperation } from "./safeDiagnostics.js";

export function createLogger(destination?: DestinationStream) {
  return pino({
  name: env.APP_NAME,
  level: env.NODE_ENV === "production" ? "info" : "debug",
  // Never serialize third-party error messages or nested error payloads containing secrets.
  serializers: { err: safeErrorDetails, operation: safeOperation },
  // Defense in depth if sensitive fields are passed to structured logging.
  redact: {
    paths: [
      "password", "newPassword", "currentPassword", "confirmPassword",
      "passwordHash", "otpHash", "tokenHash", "AUTH_PEPPER", "IP_HASH_SECRET",
      "JWT_ACCESS_SECRET", "BREVO_SMTP_KEY", "OUTBOX_ENCRYPTION_KEY",
      "payload", "otp", "challengeId", "token", "accessToken", "refreshToken", "authorization",
      "req.headers.authorization", "req.headers.cookie",
      "req.body.password", "req.body.newPassword", "req.body.currentPassword",
      "req.body.confirmPassword", "req.body.otp", "req.body.challengeId", "req.body.token",
      "req.body.accessToken", "req.body.refreshToken", "res.headers.set-cookie",
    ],
    censor: "[REDACTED]",
  },
  }, destination);
}

export const logger = createLogger();
