import "dotenv/config";
import { isIP } from "node:net";
import { z } from "zod";

// Parse bounded key rings without including secret values in validation errors.
const keyRing = z.string().default("{}").transform((value, context) => {
  try {
    const parsed = JSON.parse(value) as unknown;
    const result = z.record(z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/u),
      z.string().min(32)).safeParse(parsed);
    if (!result.success || Object.keys(result.data).length > 4) throw new Error();
    return result.data;
  } catch {
    context.addIssue({ code: "custom", message: "Expected a JSON key ring with at most four keys." });
    return z.NEVER;
  }
});

// Validate configuration once, before any service starts accepting traffic.
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4001),
  APP_NAME: z.string().min(1).default("NovaShield"),
  MONGODB_URI: z.string().min(1, "MONGODB_URI is required"),
  EXPENSEHUB_ORIGIN: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_ACCESS_AUDIENCE: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/u).default("expensehub-api"),
  // Store only digests of random 48-byte service secrets, with rotation overlap.
  INTROSPECTION_CLIENTS: z.string().default("{}").transform((value, context) => {
    try {
      const parsed = z.record(z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/u), z.object({
        audience: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/u),
        tokenHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/u)).min(1).max(2),
      }).strict()).parse(JSON.parse(value));
      if (Object.keys(parsed).length > 16) throw new Error();
      return parsed;
    } catch {
      context.addIssue({ code: "custom", message: "Expected up to sixteen service clients with audience and tokenHashes." });
      return z.NEVER;
    }
  }),
  JWT_ACCESS_KEY_ID: z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/u).default("v1"),
  JWT_PREVIOUS_KEYS: keyRing,
  PASSWORD_PEPPER_ID: z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/u).default("legacy"),
  PASSWORD_PEPPER_KEYS: keyRing,
  OUTBOX_ENCRYPTION_KEY: z.string().regex(/^[a-f0-9]{64}$/u),
  OUTBOX_KEY_ID: z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/u).default("v1"),
  OUTBOX_PREVIOUS_KEYS: keyRing,
  OUTBOX_WORKER_ENABLED: z.enum(["true", "false"]).default("false").transform(v => v === "true"),
  OUTBOX_CONCURRENCY: z.coerce.number().int().min(1).max(16).default(4),
  OUTBOX_ALERT_BACKLOG: z.coerce.number().int().min(1).default(100),
  OUTBOX_ALERT_AGE_SECONDS: z.coerce.number().int().min(1).default(60),
  AUTH_HASH_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(4),
  SECURITY_EVENT_RETENTION_DAYS: z.coerce.number().int().min(7).max(3650).default(90),
  AUTH_RECORD_RETENTION_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  TRUST_PROXY_CIDRS: z.string().default(""),
  // Only access tokens are JWTs; refresh tokens use independent random secrets.
  ACCESS_TOKEN_TTL_MINUTES: z.coerce.number().int().min(5).max(60).default(15),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(7),
  MAX_ACTIVE_SESSIONS: z.coerce.number().int().min(1).max(100).default(20),
  REFRESH_COOKIE_NAME: z.string()
    .regex(/^[A-Za-z0-9_-]+$/u)
    .default("novashield_refresh"),
  COOKIE_SECURE: z.enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
  COOKIE_SAME_SITE: z.enum(["lax", "strict", "none"]).default("lax"),
  LOGIN_WINDOW_MINUTES: z.coerce.number().int().positive().default(15),
  LOGIN_IP_LIMIT: z.coerce.number().int().positive().default(30),
  LOGIN_ACCOUNT_LIMIT: z.coerce.number().int().positive().default(10),
  IP_HASH_SECRET: z.string().min(32),
  AUTH_PEPPER: z.string().min(32),
  // Bound password input and tune Argon2 independently of password policy.
  PASSWORD_MIN_LENGTH: z.coerce.number().int().min(8).default(15),
  PASSWORD_MAX_LENGTH: z.coerce.number().int().min(64).max(1024).default(128),
  ARGON2_MEMORY_COST: z.coerce.number().int().positive().max(1048576).default(19456),
  ARGON2_TIME_COST: z.coerce.number().int().positive().max(10).default(2),
  ARGON2_PARALLELISM: z.coerce.number().int().positive().max(16).default(1),
  PASSWORD_HISTORY_LIMIT: z.coerce.number().int().min(1).max(24).default(5),
  // Reject misspellings so required screening cannot silently switch off.
  BREACHED_PASSWORD_CHECK_ENABLED: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  BREACHED_PASSWORD_FAIL_MODE: z
    .enum(["open", "closed"])
    .default("closed"),
  BREACHED_PASSWORD_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(500)
    .max(10000)
    .default(3000),
  EMAIL_PROVIDER: z.enum(["brevo", "ses"]).default("brevo"),
  BREVO_EMAIL_TRANSPORT: z.literal("smtp").default("smtp"),
  SUPPORT_EMAIL: z.string().email(),
  BREVO_SENDER_EMAIL: z.string().email(),
  BREVO_SENDER_NAME: z.string().min(1),
  BREVO_SMTP_HOST: z.string().min(1),
  BREVO_SMTP_PORT: z.coerce.number().int().positive().default(587),
  BREVO_SMTP_LOGIN: z.string().min(1),
  BREVO_SMTP_KEY: z.string().min(1),
  OTP_TTL_MINUTES: z.coerce.number().int().min(1).max(30).default(10),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(5),
  OTP_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().min(30).default(60),
  // Reset policy can be tightened independently from email verification.
  PASSWORD_RESET_OTP_TTL_MINUTES: z.coerce.number().int().min(5).max(30).default(10),
  PASSWORD_RESET_MAX_ATTEMPTS: z.coerce.number().int().min(3).max(10).default(5),
  PASSWORD_RESET_REQUEST_WINDOW_MINUTES: z.coerce.number().int().positive().default(15),
  PASSWORD_RESET_REQUEST_LIMIT: z.coerce.number().int().positive().default(5),
  // Rolling failure signals expire independently of MongoDB TTL cleanup.
  AUTH_FAILURE_WINDOW_MINUTES: z.coerce.number().int().min(1).max(60).default(15),
  AUTH_ACCOUNT_FAILURE_LIMIT: z.coerce.number().int().min(3).default(8),
  AUTH_IP_FAILURE_LIMIT: z.coerce.number().int().min(5).default(30),
  AUTH_PROGRESSIVE_DELAY_AFTER: z.coerce.number().int().min(1).default(3),
  AUTH_PROGRESSIVE_DELAY_BASE_MS: z.coerce.number().int().min(100).default(500),
  AUTH_PROGRESSIVE_DELAY_MAX_MS: z.coerce.number().int().min(500).max(10000).default(5000),
  AUTH_SPRAY_ACCOUNT_THRESHOLD: z.coerce.number().int().min(3).default(8),
  AUTH_SUSPICIOUS_SCORE_THRESHOLD: z.coerce.number().int().min(1).max(100).default(50),
}).superRefine((config, context) => {
  const invalid = (field: string, message: string) => {
    context.addIssue({ code: "custom", path: [field], message });
  };
  if (config.PASSWORD_PEPPER_ID !== "legacy"
    && !config.PASSWORD_PEPPER_KEYS[config.PASSWORD_PEPPER_ID]) {
    invalid("PASSWORD_PEPPER_KEYS", "Current pepper ID is missing.");
  }
  for (const key of Object.values(config.OUTBOX_PREVIOUS_KEYS)) {
    if (!/^[a-f0-9]{64}$/u.test(key)) {
      invalid("OUTBOX_PREVIOUS_KEYS", "Outbox keys must be 32-byte hex values.");
    }
  }
  try {
    if (new URL(config.EXPENSEHUB_ORIGIN).origin !== config.EXPENSEHUB_ORIGIN) {
      invalid("EXPENSEHUB_ORIGIN", "Use an exact origin without paths, credentials or trailing slash.");
    }
  } catch { /* The URL validator already reports invalid URLs. */ }
  for (const proxy of config.TRUST_PROXY_CIDRS.split(",").map(value => value.trim()).filter(Boolean)) {
    const [address, prefix, extra] = proxy.split("/");
    const family = isIP(address ?? "");
    if (!family || extra !== undefined || (prefix !== undefined
      && (!/^\d+$/u.test(prefix) || Number(prefix) < 1 || Number(prefix) > (family === 4 ? 32 : 128)))) {
      invalid("TRUST_PROXY_CIDRS", "Use explicit IP addresses or non-global CIDRs.");
    }
  }
  if (config.NODE_ENV === "production") {
    if (config.ARGON2_MEMORY_COST < 19456 || config.ARGON2_TIME_COST < 2) {
      invalid("ARGON2_MEMORY_COST", "Production cannot weaken the configured Argon2 baseline.");
    }
    if (new Set(config.OUTBOX_ENCRYPTION_KEY).size < 8) {
      invalid("OUTBOX_ENCRYPTION_KEY", "Use a cryptographically random encryption key.");
    }
    if (!config.EXPENSEHUB_ORIGIN.startsWith("https://")) {
      invalid("EXPENSEHUB_ORIGIN", "Production requires an HTTPS origin.");
    }
    if (config.EMAIL_PROVIDER === "ses") {
      invalid("EMAIL_PROVIDER", "SES is not implemented; select the supported SMTP provider.");
    }
    if (!config.OUTBOX_WORKER_ENABLED) {
      invalid("OUTBOX_WORKER_ENABLED", "A delivery worker is required in production.");
    }
    if (config.PASSWORD_MIN_LENGTH < 15 || !config.BREACHED_PASSWORD_CHECK_ENABLED
      || config.BREACHED_PASSWORD_FAIL_MODE !== "closed") {
      invalid("PASSWORD_MIN_LENGTH", "Production requires the enforced password security policy.");
    }
    const placeholders = (value: string) => /replace|example|test-only|change-me/iu.test(value)
      || new Set(value).size < 10;
    for (const name of ["JWT_ACCESS_SECRET", "AUTH_PEPPER", "IP_HASH_SECRET", "BREVO_SMTP_KEY"] as const) {
      if (placeholders(config[name])) invalid(name, "Production secrets must not be placeholders.");
    }
    for (const name of ["PASSWORD_PEPPER_KEYS", "JWT_PREVIOUS_KEYS"] as const) {
      if (Object.values(config[name]).some(placeholders)) invalid(name, "Key rings must not contain placeholders.");
    }
  }
  // Keep exponential backoff bounded and reject contradictory settings at startup.
  if (config.AUTH_PROGRESSIVE_DELAY_BASE_MS > config.AUTH_PROGRESSIVE_DELAY_MAX_MS) {
    context.addIssue({
      code: "custom", path: ["AUTH_PROGRESSIVE_DELAY_BASE_MS"],
      message: "Must not exceed AUTH_PROGRESSIVE_DELAY_MAX_MS.",
    });
  }

  // Browsers reject SameSite=None without Secure; production requires HTTPS.
  if (!config.COOKIE_SECURE
    && (config.COOKIE_SAME_SITE === "none" || config.NODE_ENV === "production")) {
    context.addIssue({
      code: "custom",
      path: ["COOKIE_SECURE"],
      message: "Secure cookies are required for production or SameSite=None.",
    });
  }
  if (config.REFRESH_COOKIE_NAME.startsWith("__Host-")
    || (config.REFRESH_COOKIE_NAME.startsWith("__Secure-") && !config.COOKIE_SECURE)) {
    context.addIssue({
      code: "custom",
      path: ["REFRESH_COOKIE_NAME"],
      message: "Cookie name prefix is incompatible with the configured path or security.",
    });
  }
  // Reject contradictory limits before the server accepts requests.
  if (config.PASSWORD_MIN_LENGTH > config.PASSWORD_MAX_LENGTH) {
    context.addIssue({
      code: "custom",
      path: ["PASSWORD_MIN_LENGTH"],
      message: "Must not exceed PASSWORD_MAX_LENGTH.",
    });
  }

  // Argon2 requires at least eight KiB per parallel lane.
  if (config.ARGON2_MEMORY_COST < 8 * config.ARGON2_PARALLELISM) {
    context.addIssue({
      code: "custom",
      path: ["ARGON2_MEMORY_COST"],
      message: "Must be at least eight times ARGON2_PARALLELISM.",
    });
  }
});

const result = envSchema.safeParse(process.env);
if (!result.success) {
  // Report field names and validation errors without printing secret values.
  console.error("Invalid environment configuration:");
  for (const issue of result.error.issues) {
    console.error(`- ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

export const env = Object.freeze(result.data);
