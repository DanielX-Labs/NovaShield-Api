import type { ErrorRequestHandler } from "express";
import { env } from "../config/env.js";
import { logger } from "../config/logger.js";
import { AppError } from "../utils/AppError.js";

export const errorHandler: ErrorRequestHandler = (error: unknown, req, res, next) => {
  // Let Express close a partially sent response instead of writing headers twice.
  if (res.headersSent) {
    next(error);
    return;
  }
  const requestId = req.id;
  if (error instanceof AppError) {
    if (error.statusCode >= 500) {
      logger.error({ err: error, requestId }, "Operational server error");
    }
    res.status(error.statusCode).json({
      success: false,
      error: { code: error.code, message: error.message },
      requestId,
    });
    return;
  }

  // Diagnostics stay on the server; unexpected errors get a generic response.
  logger.error({ err: error, requestId }, "Unhandled application error");
  res.status(500).json({
    success: false,
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: env.NODE_ENV === "production"
        ? "An unexpected error occurred."
        : "An unexpected error occurred. Check the server logs.",
    },
    requestId,
  });
};
