import http from "node:http";
import { app } from "./app.js";
import { env } from "./config/env.js";
import { connectDatabase, disconnectDatabase } from "./config/database.js";
import { logger } from "./config/logger.js";
import { initializeDummyPasswordHash } from "./services/password/dummyPassword.service.js";

const server = http.createServer(app);
let shuttingDown = false;

async function startServer(): Promise<void> {
  try {
    // Only accept traffic after the database connection succeeds.
    await connectDatabase();
    // Fail startup if the timing-protection hash cannot be prepared.
    await initializeDummyPasswordHash();
    if (shuttingDown) return;
    server.listen(env.PORT, () => {
      logger.info({ port: env.PORT, environment: env.NODE_ENV }, "NovaShield server started");
    });
  } catch (error) {
    logger.fatal({ err: error }, "NovaShield startup failed");
    process.exit(1);
  }
}

async function shutdown(signal: string, exitCode = 0): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, "Graceful shutdown started");

  // Stop accepting traffic, drain requests, then release the database connection.
  server.close(async (serverError) => {
    try {
      if (serverError) {
        logger.error({ err: serverError }, "HTTP server shutdown error");
      }
      await disconnectDatabase();
      logger.info("NovaShield shutdown completed");
      process.exit(serverError ? 1 : exitCode);
    } catch (error) {
      logger.error({ err: error }, "NovaShield shutdown failed");
      process.exit(1);
    }
  });

  // Do not let stalled requests hold a deployment open indefinitely.
  setTimeout(() => {
    logger.fatal("Forced shutdown after timeout");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
process.on("SIGINT", () => { void shutdown("SIGINT"); });
process.on("unhandledRejection", (reason: unknown) => {
  logger.fatal({ err: reason }, "Unhandled promise rejection");
  void shutdown("UNHANDLED_REJECTION", 1);
});
process.on("uncaughtException", (error) => {
  logger.fatal({ err: error }, "Uncaught exception");
  void shutdown("UNCAUGHT_EXCEPTION", 1);
});

void startServer();
