// Shared fixtures isolate each suite in its own temporary database.
import { email, password, external, register, seedActiveUser, login } from "../helpers/authIntegration.js";
import { describe } from "vitest";
import { it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { expect } from "vitest";
import { EmailOutboxModel } from "../../src/models/EmailOutbox.model.js";
import { processOneEmail } from "../../src/services/email/emailOutbox.service.js";
import { vi } from "vitest";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { OtpChallengeModel } from "../../src/models/OtpChallenge.model.js";
import { env } from "../../src/config/env.js";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { PasswordHistoryModel } from "../../src/models/PasswordHistory.model.js";
import { runRetention } from "../../src/services/security/retention.service.js";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";



describe("Durable email and production invariants", () => {
  it("uses an index for the time-only retention query", async () => {
    const plan = await SecurityEventModel.find({ createdAt: { $lt: new Date() } })
      .sort({ createdAt: 1 }).hint({ createdAt: 1 }).limit(500).explain("executionStats");
    expect(JSON.stringify(plan)).toContain("IXSCAN");
    expect(JSON.stringify(plan)).not.toContain("COLLSCAN");
  });
  it("commits encrypted jobs without calling SMTP and retries failed delivery", async () => {
    const result = await request(app).post("/api/v1/auth/register").send({ email, password });
    expect(result.status).toBe(202);
    expect(external.sendOtp).not.toHaveBeenCalled();
    const job = await EmailOutboxModel.findOne().select("+payload");
    expect(job?.status).toBe("PENDING");
    expect(job?.payload).not.toContain(email);
    external.sendOtp.mockRejectedValueOnce(new Error("SMTP unavailable"));
    await processOneEmail();
    expect((await EmailOutboxModel.findOne())?.status).toBe("PENDING");
    // Retry at the scheduled time; successful completion erases the ciphertext.
    await EmailOutboxModel.updateMany({}, { $set: { nextAttemptAt: new Date(0) } });
    await processOneEmail();
    const sent = await EmailOutboxModel.findOne().select("+payload");
    expect(sent?.status).toBe("SENT");
    expect(sent?.payload).toBeUndefined();
    expect(external.sendOtp).toHaveBeenCalledTimes(2);
  });
  it("rolls back registration if its durable notification cannot be queued", async () => {
    vi.spyOn(EmailOutboxModel, "create").mockRejectedValueOnce(new Error("Outbox unavailable"));
    expect((await register()).status).toBe(503);
    expect(await AuthUserModel.countDocuments()).toBe(0);
    expect(await OtpChallengeModel.countDocuments()).toBe(0);
    expect(await EmailOutboxModel.countDocuments()).toBe(0);
  });
  it("allows only one worker to claim a job and recovers an expired lease", async () => {
    await request(app).post("/api/v1/auth/register").send({ email, password });
    await EmailOutboxModel.updateMany({}, { $set: { leaseId: "crashed-worker", leaseUntil: new Date(0) } });
    await Promise.all([processOneEmail(), processOneEmail()]);
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
    expect((await EmailOutboxModel.findOne())?.status).toBe("SENT");
  });
  it("discards expired OTP jobs without sending them", async () => {
    await request(app).post("/api/v1/auth/register").send({ email, password });
    await EmailOutboxModel.updateMany({}, { $set: { expiresAt: new Date(0) } });
    await processOneEmail();
    expect(external.sendOtp).not.toHaveBeenCalled();
    expect((await EmailOutboxModel.findOne().select("+payload"))?.payload).toBeUndefined();
    expect((await EmailOutboxModel.findOne())?.status).toBe("EXPIRED");
  });
  it("upgrades hashes after login without changing password version or history", async () => {
    await seedActiveUser();
    Object.assign(env, { PASSWORD_PEPPER_ID: "v2", PASSWORD_PEPPER_KEYS: { v2: "new-integration-test-password-pepper-key" } });
    try {
      expect((await login()).status).toBe(200);
      const credential = await CredentialModel.findOne().select("+passwordHash");
      expect(credential?.passwordHash.startsWith("ns1:v2:")).toBe(true);
      expect(credential?.passwordVersion).toBe(1);
      expect(await PasswordHistoryModel.countDocuments()).toBe(0);
      expect((await login()).status).toBe(200);
    } finally { Object.assign(env, { PASSWORD_PEPPER_ID: "legacy", PASSWORD_PEPPER_KEYS: {} }); }
  });
  it("retains live replay evidence and deletes only expired records beyond grace", async () => {
    await seedActiveUser();
    await login();
    await runRetention();
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
    await RefreshTokenModel.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 8 * 86400_000) } });
    await SessionModel.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 8 * 86400_000) } });
    await runRetention();
    expect(await RefreshTokenModel.countDocuments()).toBe(0);
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await AuthUserModel.countDocuments()).toBe(1);
  });
});
