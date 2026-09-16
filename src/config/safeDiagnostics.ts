// Diagnostic fields are closed vocabularies: never copy messages, stacks or causes.
const names = new Set([
  "Error", "AppError", "TypeError", "ReferenceError", "RangeError", "SyntaxError",
  "MongoServerError", "MongoNetworkError", "MongoServerSelectionError",
  "MongooseServerSelectionError", "ValidationError", "CastError",
]);
const codes = new Set([
  "EAUTH", "EENVELOPE", "ECONNECTION", "ESOCKET", "ETIMEDOUT",
  "ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN",
  "AUTH_UNAVAILABLE", "INTERNAL_SERVER_ERROR", "PASSWORD_SECURITY_CHECK_UNAVAILABLE",
]);
const operations = new Set([
  "http.request", "database.connect", "database.disconnect", "server.start",
  "server.shutdown", "email.send", "email.verify", "outbox.delivery",
  "outbox.maintenance", "process.unhandled",
  "auth.login", "auth.transaction", "auth.registration",
]);

export function safeOperation(value: unknown): string {
  return typeof value === "string" && operations.has(value) ? value : "unknown";
}

export function safeErrorDetails(value: unknown) {
  try {
    const error = value as { name?: unknown; code?: unknown } | null;
    const type = typeof error?.name === "string" && names.has(error.name)
      ? error.name : "Error";
    const code = error?.code === 11000 ? "DUPLICATE_KEY"
      : typeof error?.code === "string" && codes.has(error.code) ? error.code : "UNCLASSIFIED";
    const category = type.includes("Mongo") || type === "CastError" || code === "DUPLICATE_KEY"
      ? "DATABASE" : ["EAUTH", "EENVELOPE"].includes(code) ? "EMAIL"
      : code.startsWith("E") && code !== "UNCLASSIFIED" ? "NETWORK"
      : ["TypeError", "ReferenceError", "RangeError", "SyntaxError"].includes(type)
        ? "PROGRAMMING" : type === "AppError" ? "APPLICATION" : "UNKNOWN";
    return { type, code, category };
  } catch {
    // Even hostile accessor properties on an error must not break logging.
    return { type: "Error", code: "UNCLASSIFIED", category: "UNKNOWN" };
  }
}
