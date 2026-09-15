import { Router } from "express";
import { authenticate } from "../middleware/authenticate.middleware.js";
import { requireAuthOrigin } from "../middleware/authOrigin.middleware.js";
import { authAbuseLimit } from "../middleware/authAbuse.middleware.js";
import {
  listSessionsController, revokeAllSessionsController, revokeSessionController,
} from "../controllers/session.controller.js";

export const sessionRouter = Router();
const limit = authAbuseLimit("session-management-ip", 60, false, 5 * 60_000);

// Apply authentication only to matched paths, preserving normal 404 behavior.
sessionRouter.get(
  "/auth/sessions", limit, authenticate, listSessionsController,
);
sessionRouter.delete(
  "/auth/sessions/:sessionId",
  limit, requireAuthOrigin, authenticate, revokeSessionController,
);
sessionRouter.delete(
  "/auth/sessions",
  limit, requireAuthOrigin, authenticate, revokeAllSessionsController,
);
