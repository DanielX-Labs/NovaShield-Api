import nodemailer from "nodemailer";
import { env } from "../../config/env.js";
import { logger } from "../../config/logger.js";
import type { EmailProvider, SendEmailInput } from "./email.types.js";

// Require encryption: port 465 uses TLS directly; other ports use STARTTLS.
const transporter = nodemailer.createTransport({
  host: env.BREVO_SMTP_HOST,
  port: env.BREVO_SMTP_PORT,
  secure: env.BREVO_SMTP_PORT === 465,
  requireTLS: true,
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 30_000,
  auth: {
    user: env.BREVO_SMTP_LOGIN,
    pass: env.BREVO_SMTP_KEY,
  },
});

export const brevoSmtpProvider: EmailProvider = {
  async send(input: SendEmailInput): Promise<void> {
    const result = await transporter.sendMail({
      from: {
        name: env.BREVO_SENDER_NAME,
        address: env.BREVO_SENDER_EMAIL,
      },
      to: input.to,
      replyTo: env.SUPPORT_EMAIL,
      subject: input.subject,
      text: input.text,
      html: input.html,
    }).catch(error => {
      logger.error({ err: error, operation: "email.send" }, "SMTP send failed");
      throw error;
    });

    // Log delivery metadata only, never the recipient, OTP, or message body.
    logger.info(
      { messageId: result.messageId },
      "Transactional email accepted by provider",
    );
  },
};

// Explicit diagnostic only; do not run for each request or send a test email.
export async function verifyBrevoConnection(): Promise<void> {
  await transporter.verify().catch(error => {
    logger.error({ err: error, operation: "email.verify" }, "SMTP verification failed");
    throw error;
  });
  logger.info("Brevo SMTP connection verified");
}
