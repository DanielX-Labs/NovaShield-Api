import { Router } from "express";
import { env } from "../config/env.js";
import { authenticate } from "../middleware/authenticate.middleware.js";
import { requireAuthOrigin } from "../middleware/authOrigin.middleware.js";
import { authAbuseLimit } from "../middleware/authAbuse.middleware.js";
import { validate } from "../middleware/validate.middleware.js";
import {
  changePasswordSchema,
  passwordResetRequestSchema,
  passwordResetConfirmSchema,
} from "../validators/password.validators.js";
import {
  changePasswordController,
  passwordResetRequestController,
  passwordResetConfirmController,
} from "../controllers/password.controller.js";

export const passwordRouter = Router();

// Sensitive responses must not be cached, including validation failures.
passwordRouter.use("/password", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

passwordRouter.post("/password/change",
  authAbuseLimit("password-change-ip", 10),
  requireAuthOrigin,
  authenticate,
  validate(changePasswordSchema),
  changePasswordController,
);

// Source admission is separate from transactional email issuance budgets.
const resetWindow = env.PASSWORD_RESET_REQUEST_WINDOW_MINUTES * 60_000;
passwordRouter.post("/password/reset/request",
  authAbuseLimit("password-reset-ip", env.PASSWORD_RESET_REQUEST_LIMIT, false, resetWindow),
  requireAuthOrigin,
  validate(passwordResetRequestSchema),
  passwordResetRequestController,
);

// The challenge's persisted attempt budget remains authoritative across IPs.
passwordRouter.post("/password/reset/confirm",
  authAbuseLimit("password-reset-confirm-ip", 10),
  requireAuthOrigin,
  validate(passwordResetConfirmSchema),
  passwordResetConfirmController,
);
