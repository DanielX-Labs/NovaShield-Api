import { Router } from "express";
import { validate } from "../middleware/validate.middleware.js";
import { createRegistrationControllers } from "../controllers/registration.controller.js";
import { authAbuseLimit } from "../middleware/authAbuse.middleware.js";
import {
  registrationService,
  type createRegistrationService,
} from "../services/auth/registration.service.js";
import { loginController, refreshController, logoutController } from "../controllers/auth.controller.js";
import { loginRateLimit, refreshRateLimit } from "../middleware/authRateLimit.middleware.js";
import { loginSchema, registrationSchema, resendSchema, verificationSchema } from "../validators/auth.validators.js";
import { authenticate } from "../middleware/authenticate.middleware.js";
import { requireAuthOrigin } from "../middleware/authOrigin.middleware.js";

export function createAuthRouter(
  service: ReturnType<typeof createRegistrationService> = registrationService,
): Router {
  const router = Router();
  const controllers = createRegistrationControllers(service);

  // These responses must not be cached by browsers or intermediaries.
  router.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  router.post("/auth/register",
    requireAuthOrigin,
    authAbuseLimit("register-ip", 10),
    validate(registrationSchema),
    controllers.register,
  );

  router.post("/auth/login",
    // A larger shared IPv6 budget limits address rotation without using host-sized quotas.
    authAbuseLimit("login-network", 120, false, 15 * 60_000, true, true),
    loginRateLimit,
    requireAuthOrigin,
    validate(loginSchema),
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
    requireAuthOrigin,
    authAbuseLimit("resend-ip", 10),
    validate(resendSchema),
    controllers.resend,
  );

  router.post("/email/verify",
    requireAuthOrigin,
    authAbuseLimit("verify-ip", 50),
    validate(verificationSchema),
    controllers.verify,
  );
  return router;
}
