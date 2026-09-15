import type { RequestHandler } from "express";
import type { ZodType } from "zod";
import { AppError } from "../utils/AppError.js";

// Never echo raw validation errors: they may contain submitted secrets.
export function validate(schema: ZodType): RequestHandler {
  return (req, _res, next) => {
    const result = schema.safeParse({ body: req.body });
    if (!result.success) {
      next(new AppError("Invalid request fields.", 400, "VALIDATION_ERROR"));
      return;
    }
    req.body = (result.data as { body: unknown }).body;
    next();
  };
}
