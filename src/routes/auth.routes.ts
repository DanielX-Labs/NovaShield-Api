import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { env } from "../config/env.js";
import { AppError } from "../utils/AppError.js";
import { authAbuseLimit } from "../middleware/authAbuse.middleware.js";
import {
  registrationService,
  type createRegistrationService,
} from "../services/auth/registration.service.js";
import { securityContext } from "../services/security/securityEvent.service.js";
import { loginController, refreshController, logoutController } from "../controllers/auth.controller.js";
import { loginRateLimit, refreshRateLimit } from "../middleware/authRateLimit.middleware.js";
import { loginSchema } from "../validators/auth.validators.js";
import { authenticate } from "../middleware/authenticate.middleware.js";
import { requireAuthOrigin } from "../middleware/authOrigin.middleware.js";

// Validate and normalize only identity fields; passwords remain byte-for-byte input.
const emailSchema = z.string().trim().max(254).email().toLowerCase();
const registrationSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(env.PASSWORD_MAX_LENGTH),
  name: z.string().trim().min(1).max(100).optional(),
}).strict();
const resendSchema = z.object({ email: emailSchema }).strict();
const verificationSchema = z.object({
  challengeId: z.string().regex(/^[a-f0-9]{24}$/u),
  otp: z.string().regex(/^\d{6}$/u),
}).strict();

function validate(schema: z.ZodType): RequestHandler {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      // Never echo input or raw Zod errors into logs or client responses.
      next(new AppError("Invalid request fields.", 400, "VALIDATION_ERROR"));
      return;
    }
    req.body = result.data;
    next();
  };
}

export function createAuthRouter(
  service: ReturnType<typeof createRegistrationService> = registrationService,
): Router {
  const router = Router();

  // These responses must not be cached by browsers or intermediaries.
  router.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  router.post("/auth/register",
    authAbuseLimit("register-ip", 10),
    validate(registrationSchema),
    authAbuseLimit("verification-email", 5, true),
    async (req, res) => {
      const result = await service.register(req.body, securityContext(req));
      res.status(202).json({
        success: true,
        message: "If eligible, a verification code will be sent to this address.",
        data: result,
        requestId: req.id,
      });
    },
  );

  router.post("/auth/login",
    loginRateLimit,
    requireAuthOrigin,
    (req, _res, next) => {
      const result = loginSchema.safeParse({ body: req.body });
      if (!result.success) {
        next(new AppError("Invalid request fields.", 400, "VALIDATION_ERROR"));
        return;
      }
      req.body = result.data.body;
      next();
    },
    loginController,
  );

  router.post("/auth/refresh",
    refreshRateLimit, requireAuthOrigin, refreshController,
  );
  router.post("/auth/logout",
    authAbuseLimit("logout-ip", 60, false, 5 * 60_000),
    requireAuthOrigin, authenticate, logoutController,
  );

  router.post("/email/resend",
    authAbuseLimit("resend-ip", 10),
    validate(resendSchema),
    authAbuseLimit("verification-email", 5, true),
    async (req, res) => {
      const result = await service.resend(req.body.email, securityContext(req));
      // Same status and shape for cooldown, unknown, and already-active accounts.
      res.status(202).json({
        success: true,
        message: "If eligible, a verification code will be sent to this address.",
        data: result,
        requestId: req.id,
      });
    },
  );

  router.post("/email/verify",
    authAbuseLimit("verify-ip", 50),
    validate(verificationSchema),
    async (req, res) => {
      await service.verify(req.body.challengeId, req.body.otp, securityContext(req));
      res.status(200).json({
        success: true,
        message: "Email verified.",
        requestId: req.id,
      });
    },
  );
  return router;
}
