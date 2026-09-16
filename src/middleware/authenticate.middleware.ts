import type { RequestHandler } from "express";
import { resolveAccessIdentity } from "../services/session/accessIdentity.service.js";
import { AppError } from "../utils/AppError.js";

export const authenticate: RequestHandler = async (req, _res, next) => {
  const authorization = req.get("authorization");
  if (!authorization?.startsWith("Bearer ")) {
    next(new AppError("Authentication is required.", 401, "AUTHENTICATION_REQUIRED"));
    return;
  }
  try {
    // Share revocation and credential-version checks with service introspection.
    const identity = await resolveAccessIdentity(authorization.slice(7));
    if (!identity) {
      throw new AppError("Authentication is invalid or expired.", 401, "INVALID_ACCESS_TOKEN");
    }
    req.auth = identity;
    next();
  } catch (error) {
    next(error);
  }
};
