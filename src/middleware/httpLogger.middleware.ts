import pinoHttp from "pino-http";
import { logger } from "../config/logger.js";

export const httpLogger = pinoHttp({
  logger,
  customProps(req) {
    return { requestId: req.id };
  },
  // Keep HTTP logs small and exclude request bodies and headers.
  serializers: {
    req(req) {
      // Query strings can contain mistakenly supplied OTPs or passwords.
      return {
        method: req.method,
        // Unknown paths may contain accidentally pasted secrets. Log only known route shapes.
        url: safeRequestPath(req.url),
        requestId: req.id,
      };
    },
    res(res) {
      return { statusCode: res.statusCode };
    },
  },
});

export function safeRequestPath(url?: string): string {
  const path = url?.split("?")[0] ?? "";
  if (/^\/api\/v1\/(health|ready|auth\/(register|login|refresh|logout|sessions)|email\/(verify|resend)|password\/(change|reset\/(request|confirm)))$/u.test(path)) return path;
  if (/^\/api\/v1\/auth\/sessions\/[^/]+$/u.test(path)) return "/api/v1/auth/sessions/:sessionId";
  return "[unmatched]";
}
