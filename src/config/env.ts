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
