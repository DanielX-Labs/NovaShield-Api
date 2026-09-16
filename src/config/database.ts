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
    logger.error({ err: error, operation: "database.connect" }, "MongoDB connection failed");
    throw error;
  }
}

export async function disconnectDatabase(): Promise<void> {
  try {
    await mongoose.disconnect();
    logger.info("MongoDB connection closed");
  } catch (error) {
    logger.error({ err: error, operation: "database.disconnect" }, "Failed to close MongoDB connection");
    throw error;
  }
}

let draining = false;
export function markDatabaseDraining(): void { draining = true; }
export async function isDatabaseReady(): Promise<boolean> {
  if (draining || mongoose.connection.readyState !== 1 || !mongoose.connection.db) return false;
  try {
    // Ping the database instead of relying only on the driver's cached connection state.
    await mongoose.connection.db.command({ ping: 1 }, { timeoutMS: 1500 });
    return !draining;
  } catch { return false; }
}
