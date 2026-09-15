import type { RequestHandler } from "express";
import { env } from "../config/env.js";
import { AppError } from "../utils/AppError.js";

// Cookie-authenticated refresh requests need an origin check in addition to CORS.
export const requireAuthOrigin: RequestHandler = (req, _res, next) => {
  const origin = req.get("origin");
  if ((origin && origin !== env.EXPENSEHUB_ORIGIN)
    || (!origin && req.get("sec-fetch-site") === "cross-site")) {
    next(new AppError("Request origin is not allowed.", 403, "ORIGIN_NOT_ALLOWED"));
    return;
  }
  // Native API clients can omit Origin; browsers must match the configured origin.
  next();
};
