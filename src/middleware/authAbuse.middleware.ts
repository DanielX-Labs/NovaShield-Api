import type { RequestHandler } from "express";
import { AbuseBucketModel } from "../models/AbuseBucket.model.js";
import { AppError } from "../utils/AppError.js";
import { logger } from "../config/logger.js";
import { hashNetworkAddress } from "../services/security/networkIdentity.service.js";
import {
  hashSecurityIdentifier,
  recordSecurityEvent,
  securityContext,
} from "../services/security/securityEvent.service.js";

const WINDOW_MS = 15 * 60 * 1000;

// Atomic increments enforce one shared budget even when requests race.
export function authAbuseLimit(
  scope: string,
  limit: number,
  byEmail = false,
  windowMs = WINDOW_MS,
  skipSuccessfulRequests = false,
  byNetwork = false,
): RequestHandler {
  return async (req, res, next) => {
    try {
      const context = securityContext(req);
      const identifier = byNetwork ? hashNetworkAddress(req.ip) : byEmail
        ? hashSecurityIdentifier(req.body.email)
        : context.ipHash;
      // IPv4 stays under the existing host budget; do not group unrelated IPv4 users.
      if (byNetwork && !identifier) { next(); return; }
      const window = Math.floor(Date.now() / windowMs);
      const id = `${scope}:${identifier}:${window}`;
      let bucket;

      try {
        bucket = await AbuseBucketModel.findOneAndUpdate(
          { _id: id },
          {
            $inc: { count: 1 },
            $setOnInsert: {
              expiresAt: new Date((window + 2) * windowMs),
            },
          },
          { upsert: true, returnDocument: "after" },
        );
      } catch (error) {
        // Concurrent first requests may race on the same unique bucket key.
        if ((error as { code?: number }).code !== 11000) throw error;
        bucket = await AbuseBucketModel.findOneAndUpdate(
          { _id: id },
          { $inc: { count: 1 } },
          { returnDocument: "after" },
        );
      }

      if (!bucket || bucket.count > limit) {
        // Record the transition once per bucket to avoid unbounded audit spam.
        if (bucket?.count === limit + 1) {
          await recordSecurityEvent(
            "AUTH_RATE_LIMITED", context, undefined, undefined, "LOW",
          );
        }
        res.setHeader(
          "Retry-After",
          Math.ceil(((window + 1) * windowMs - Date.now()) / 1000),
        );
        throw new AppError(
          "Too many requests. Please try again later.",
          429,
          "AUTH_RATE_LIMITED",
        );
      }
      if (skipSuccessfulRequests) {
        // In-flight attempts count immediately; release only completed successes.
        res.once("finish", () => {
          if (res.statusCode >= 400) return;
          void AbuseBucketModel.updateOne(
            { _id: id, count: { $gt: 0 } },
            { $inc: { count: -1 } },
          ).catch(() => {
            // Keep the stricter counter on failure, without unhandled rejections.
            logger.warn("Could not release a successful login rate-limit reservation.");
          });
        });
      }
      next();
    } catch (error) {
      // Counter storage failure must not silently disable abuse protection.
      next(error instanceof AppError ? error : new AppError(
        "Authentication is temporarily unavailable.",
        503,
        "AUTH_UNAVAILABLE",
      ));
    }
  };
}
