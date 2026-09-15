import { env } from "../../config/env.js";
import type { EmailProvider } from "./email.types.js";

// Load only the selected provider; SES does not initialize Brevo credentials.
async function getProvider(): Promise<EmailProvider> {
  switch (env.EMAIL_PROVIDER) {
    case "brevo":
      return (await import("./brevoSmtp.provider.js")).brevoSmtpProvider;
    case "ses":
      throw new Error("Amazon SES provider has not been configured yet.");
    default:
      throw new Error("Unsupported email provider.");
  }
}

export async function sendVerificationOtpEmail(
  email: string,
  otp: string,
): Promise<void> {
  // Only numeric OTPs can enter the HTML template.
  if (!/^\d{6}$/u.test(otp)) {
    throw new Error("Verification code must contain six digits.");
  }
  const provider = await getProvider();

  // Include both plain text and HTML for mail-client compatibility.
  await provider.send({
    to: email,
    subject: "Verify your NovaPay email address",
    text:
      `Your NovaPay verification code is ${otp}. ` +
      `It expires in ${env.OTP_TTL_MINUTES} minutes. ` +
      "Never share this code with anyone. " +
      "If you did not request this code, you can ignore this email.",
    html: `
      <div>
        <h2>Verify your email</h2>
        <p>Use the following verification code:</p>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">
          ${otp}
        </p>
        <p>This code expires in ${env.OTP_TTL_MINUTES} minutes.</p>
        <p>Never share this code with anyone.</p>
        <p>If you did not request this code, you can ignore this email.</p>
      </div>
    `,
  });
}
