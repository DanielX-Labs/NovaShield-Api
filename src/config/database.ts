import mongoose from "mongoose";
import { env } from "./env.js";
import { logger } from "./logger.js";
import { initializeAuthStorage } from "./authStorage.js";

export async function connectDatabase(): Promise<void> {
  try {
    // Fail startup promptly when MongoDB cannot be reached.
    await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    await initializeAuthStorage();
    logger.info("MongoDB connection established");
  } catch (error) {
    logger.error({ err: error }, "MongoDB connection failed");
    throw error;
  }
}

export async function disconnectDatabase(): Promise<void> {
  try {
    await mongoose.disconnect();
    logger.info("MongoDB connection closed");
  } catch (error) {
    logger.error({ err: error }, "Failed to close MongoDB connection");
    throw error;
  }
}

export function isDatabaseReady(): boolean {
  // Mongoose state 1 means an active database connection.
  return mongoose.connection.readyState === 1;
}
