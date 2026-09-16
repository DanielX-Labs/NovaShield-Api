import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { env } from "./config/env.js";
import { requestIdMiddleware } from "./middleware/requestId.middleware.js";
import { httpLogger } from "./middleware/httpLogger.middleware.js";
import { notFoundHandler } from "./middleware/notFound.middleware.js";
import { errorHandler } from "./middleware/error.middleware.js";
import { healthRouter } from "./routes/health.routes.js";
import { createAuthRouter } from "./routes/auth.routes.js";
import { sessionRouter } from "./routes/session.routes.js";
import { passwordRouter } from "./routes/password.routes.js";
import { introspectionRouter } from "./routes/introspection.routes.js";

export const app = express();
app.disable("x-powered-by");
// Trust only explicitly configured proxy CIDRs, never arbitrary forwarding headers.
const trustedProxies = env.TRUST_PROXY_CIDRS?.split(",").map(value => value.trim()).filter(Boolean);
if (trustedProxies?.length) app.set("trust proxy", trustedProxies);

// Order matters: every request, including failures, gets an ID and logging.
app.use(requestIdMiddleware);
app.use(httpLogger);
app.use(helmet());
app.use(cors({
  origin: env.EXPENSEHUB_ORIGIN,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
}));

// Authentication requests should never need large payloads.
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
// Read opaque refresh cookies before authentication routes execute.
app.use(cookieParser());
app.use("/api/v1", healthRouter);
app.use("/api/v1", createAuthRouter());
app.use("/api/v1", sessionRouter);
app.use("/api/v1", passwordRouter);
app.use("/api/v1", introspectionRouter);

// Fallback handlers must come after all routes.
app.use(notFoundHandler);
app.use(errorHandler);
