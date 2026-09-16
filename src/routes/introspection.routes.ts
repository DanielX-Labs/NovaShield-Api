import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { env } from "../config/env.js";
import { AppError } from "../utils/AppError.js";
import { authAbuseLimit } from "../middleware/authAbuse.middleware.js";
import { resolveAccessIdentity } from "../services/session/accessIdentity.service.js";

export const introspectionRouter = Router();

// Service credentials only authorize introspection; they cannot sign user JWTs.
const authenticateClient: RequestHandler = (req, _res, next) => {
  if (req.get("origin")) {
    next(new AppError("Service authentication is required.", 403, "SERVICE_CLIENT_REQUIRED"));
    return;
  }
  const match = /^Bearer ([a-zA-Z0-9_-]{1,32})\.([a-zA-Z0-9_-]{64})$/u
    .exec(req.get("authorization") ?? "");
  const client = match ? env.INTROSPECTION_CLIENTS?.[match[1]!] : undefined;
  const supplied = createHash("sha256").update(match?.[2] ?? "").digest();
  // Only fixed-length digests are compared. Unknown IDs still perform comparison.
  let matches = false;
  for (const digest of client?.tokenHashes ?? ["0".repeat(64)]) {
    matches = timingSafeEqual(supplied, Buffer.from(digest, "hex")) || matches;
  }
  if (!match || !client || !matches || client.audience !== env.JWT_ACCESS_AUDIENCE) {
    next(new AppError("Service authentication is invalid.", 401, "INVALID_SERVICE_CLIENT"));
    return;
  }
  next();
};

introspectionRouter.post("/internal/token/introspect",
  (_req, res, next) => { res.setHeader("Cache-Control", "no-store"); next(); },
  authAbuseLimit("introspection-ip", 600, false, 60_000),
  authenticateClient,
  async (req, res) => {
    // Reject malformed envelopes without echoing tokens or parser diagnostics.
    const body = z.object({ token: z.string().min(1).max(4096) }).strict().safeParse(req.body);
    if (!body.success) throw new AppError("Invalid introspection request.", 400, "VALIDATION_ERROR");
    const identity = await resolveAccessIdentity(body.data.token);
    if (!identity) { res.json({ active: false }); return; }
    // Application authorization belongs to the caller, keyed by this verified subject.
    res.json({ active: true, sub: identity.userId, sid: identity.sessionId,
      ver: identity.passwordVersion, iss: "novashield", aud: env.JWT_ACCESS_AUDIENCE });
  },
);
