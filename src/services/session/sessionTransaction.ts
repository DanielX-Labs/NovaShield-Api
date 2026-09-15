import mongoose, { type ClientSession } from "mongoose";
import { AppError } from "../../utils/AppError.js";

// Database failures fail closed without leaking token documents in diagnostics.
export async function sessionTransaction<T>(
  work: (transaction: ClientSession) => Promise<T>,
): Promise<T> {
  try {
    return await mongoose.connection.transaction(work);
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      "Session security is temporarily unavailable.",
      503,
      "AUTH_UNAVAILABLE",
    );
  }
}
