import type { Request, Response } from "express";

export function notFoundHandler(req: Request, res: Response): void {
  // Avoid reflecting internal routes or implementation details to callers.
  res.status(404).json({
    success: false,
    error: { code: "RESOURCE_NOT_FOUND", message: "The requested resource was not found." },
    requestId: req.id,
  });
}
