import "dotenv/config";
import { z } from "zod";

// Validate configuration once, before any service starts accepting traffic.
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4001),
  APP_NAME: z.string().min(1).default("NovaShield"),
  MONGODB_URI: z.string().min(1, "MONGODB_URI is required"),
  EXPENSEHUB_ORIGIN: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  ACCESS_TOKEN_TTL: z.string().default("15m"),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),
  AUTH_PEPPER: z.string().min(32),
  // Bound password input and tune Argon2 independently of password policy.
  PASSWORD_MIN_LENGTH: z.coerce.number().int().min(8).default(15),
  PASSWORD_MAX_LENGTH: z.coerce.number().int().min(64).max(1024).default(128),
  ARGON2_MEMORY_COST: z.coerce.number().int().positive().default(19456),
  ARGON2_TIME_COST: z.coerce.number().int().positive().default(2),
  ARGON2_PARALLELISM: z.coerce.number().int().positive().default(1),
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
}).superRefine((config, context) => {
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
