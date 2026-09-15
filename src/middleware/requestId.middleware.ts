import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Generate our own ID instead of trusting a caller-supplied identifier.
  req.id = randomUUID();
  res.setHeader("X-Request-Id", req.id);
  next();
}
