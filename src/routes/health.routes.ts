import { Router } from "express";
import { isDatabaseReady } from "../config/database.js";

export const healthRouter = Router();

// Liveness checks the process; readiness also checks its database dependency.
healthRouter.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok", service: "NovaShield", timestamp: new Date().toISOString() });
});

healthRouter.get("/ready", async (_req, res) => {
  if (!await isDatabaseReady()) {
    res.status(503).json({ status: "not_ready" });
    return;
  }
  res.status(200).json({ status: "ready" });
});
