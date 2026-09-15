import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock SMTP and logging so no email is sent and no credentials are needed.
const mocks = vi.hoisted(() => ({
  sendMail: vi.fn(),
  verify: vi.fn(),
  createTransport: vi.fn(),
  transportOptions: {} as Record<string, unknown>,
  info: vi.fn(),
}));
vi.mock("nodemailer", () => ({
  default: {
    createTransport: mocks.createTransport.mockImplementation((options) => {
      mocks.transportOptions = options;
      return mocks;
    }),
  },
}));
vi.mock("../../src/config/logger.js", () => ({
  logger: { info: mocks.info },
}));
vi.mock("../../src/config/env.js", () => ({
  env: {
    EMAIL_PROVIDER: "brevo",
    BREVO_SMTP_HOST: "smtp.example.com",
    BREVO_SMTP_PORT: 587,
    BREVO_SMTP_LOGIN: "test",
    BREVO_SMTP_KEY: "test-secret",
    BREVO_SENDER_NAME: "NovaPay Security",
    BREVO_SENDER_EMAIL: "sender@example.com",
    SUPPORT_EMAIL: "support@example.com",
    OTP_TTL_MINUTES: 10,
    PASSWORD_RESET_OTP_TTL_MINUTES: 15,
  },
}));
import { env } from "../../src/config/env.js";
import { sendVerificationOtpEmail, sendPasswordResetOtpEmail, sendPasswordChangedEmail } from "../../src/services/email/email.service.js";
import { verifyBrevoConnection } from "../../src/services/email/brevoSmtp.provider.js";

beforeEach(() => {
  mocks.sendMail.mockReset().mockResolvedValue({ messageId: "message-1" });
  mocks.info.mockClear();
  Object.assign(env, { EMAIL_PROVIDER: "brevo" });
});

describe("Email boundary", () => {
  it("requires TLS and sends plain text plus HTML", async () => {
    await sendVerificationOtpEmail("customer@example.com", "123456");
    expect(mocks.transportOptions).toEqual(
      expect.objectContaining({ secure: false, requireTLS: true }),
    );
    expect(mocks.sendMail).toHaveBeenCalledWith(expect.objectContaining({
      to: "customer@example.com",
      replyTo: "support@example.com",
      text: expect.stringContaining("123456"),
      html: expect.stringContaining("10 minutes"),
    }));
    expect(mocks.info).toHaveBeenCalledWith(
      { messageId: "message-1" },
      "Transactional email accepted by provider",
    );
  });

  it("rejects template injection and unsupported SES", async () => {
    await expect(sendVerificationOtpEmail("customer@example.com", "<script>"))
      .rejects.toThrow("six digits");
    Object.assign(env, { EMAIL_PROVIDER: "ses" });
    await expect(sendVerificationOtpEmail("customer@example.com", "123456"))
      .rejects.toThrow("Amazon SES");
    expect(mocks.sendMail).not.toHaveBeenCalled();
  });

  it("propagates delivery failures", async () => {
    mocks.sendMail.mockRejectedValue(new Error("SMTP unavailable"));
    await expect(sendVerificationOtpEmail("customer@example.com", "123456"))
      .rejects.toThrow("SMTP unavailable");
    expect(mocks.info).not.toHaveBeenCalled();
  });

  it("checks the connection explicitly without sending mail", async () => {
    await verifyBrevoConnection();
    expect(mocks.verify).toHaveBeenCalled();
    expect(mocks.sendMail).not.toHaveBeenCalled();
  });
});

// Templates use their own expiry and do not include credentials in change notices.
describe("Password lifecycle email", () => {
  it("uses the reset expiry and rejects nonnumeric template input", async () => {
    await sendPasswordResetOtpEmail("customer@example.com", "123456");
    expect(mocks.sendMail).toHaveBeenCalledWith(expect.objectContaining({
      text: expect.stringContaining("15 minutes"),
      html: expect.stringContaining("123456"),
    }));
    await expect(sendPasswordResetOtpEmail("customer@example.com", "<script>"))
      .rejects.toThrow("six digits");
  });
  it("notifies the user of session revocation", async () => {
    await sendPasswordChangedEmail("customer@example.com");
    expect(mocks.sendMail).toHaveBeenCalledWith(expect.objectContaining({
      text: expect.stringContaining("all sessions were signed out"),
    }));
  });
});
