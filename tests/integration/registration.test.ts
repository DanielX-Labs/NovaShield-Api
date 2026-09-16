// Shared fixtures isolate each suite in its own temporary database.
import { email, register, password, sentOtp, models, external, allowResend, drainEmails } from "../helpers/authIntegration.js";
import { describe } from "vitest";
import { it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { expect } from "vitest";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { verifyPassword } from "../../src/services/password/passwordHash.service.js";
import { PasswordHistoryModel } from "../../src/models/PasswordHistory.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { OtpChallengeModel } from "../../src/models/OtpChallenge.model.js";
import { vi } from "vitest";
import { AbuseBucketModel } from "../../src/models/AbuseBucket.model.js";
import { EmailOutboxModel } from "../../src/models/EmailOutbox.model.js";


describe("Registration and email verification", () => {
  it("returns safe errors for malformed JSON and oversized bodies", async () => {
    const invalid = await request(app).post("/api/v1/auth/register")
      .set("Content-Type", "application/json")
      .send('{"password":"private-value",');
    expect(invalid.status).toBe(400);
    expect(invalid.text).not.toContain("private-value");
    const oversized = await request(app).post("/api/v1/auth/register")
      .send({ email, password: "x".repeat(40_000) });
    expect(oversized.status).toBe(413);
  });
  it("creates pending identity, credentials and audit records then activates once", async () => {
    const response = await register("  CUSTOMER@example.com  ");
    expect(response.status).toBe(202);
    const challengeId = response.body.data.challengeId;
    const user = await AuthUserModel.findOne({ emailNormalized: email }).lean();
    expect(user).toMatchObject({
      status: "PENDING_VERIFICATION", isEmailVerified: false,
    });
    const credential = await CredentialModel.findOne({ userId: user!._id })
      .select("+passwordHash").lean();
    expect(credential!.passwordHash).toMatch(/^ns1:legacy:\$argon2id\$/u);
    expect(await verifyPassword(credential!.passwordHash, password)).toBe(true);
    expect(await PasswordHistoryModel.countDocuments()).toBe(0);
    expect(await SecurityEventModel.distinct("eventType")).toEqual(
      expect.arrayContaining(["AUTH_REGISTERED", "AUTH_EMAIL_OTP_SENT"]),
    );

    // Inspect raw stored records to catch accidental plaintext persistence.
    const otp = sentOtp();
    for (const model of models) {
      const documents = await model.collection.find({}).toArray();
      const stored = JSON.stringify(documents);
      expect(stored).not.toContain(password);
      expect(stored).not.toContain('"' + otp + '"');
      expect(stored).not.toContain('"otp":');
      expect(stored).not.toContain('"password":');
    }
    expect(response.text).not.toContain(otp);

    const result = await request(app).post("/api/v1/email/verify")
      .send({ challengeId, otp });
    expect(result.status).toBe(200);
    expect(await AuthUserModel.findById(user!._id)).toMatchObject({
      status: "ACTIVE", isEmailVerified: true,
    });
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_EMAIL_VERIFIED",
    })).toBe(1);
    expect((await request(app).post("/api/v1/email/verify")
      .send({ challengeId, otp })).status).toBe(400);
  });

  it("does not overwrite credentials or send email on duplicate registration", async () => {
    await register();
    const before = await CredentialModel.findOne().select("+passwordHash").lean();
    const duplicate = await request(app).post("/api/v1/auth/register").send({
      email: "CUSTOMER@example.com",
      password: "Velvet-Cedar!Compass-93",
    });
    expect(duplicate.status).toBe(202);
    expect(await AuthUserModel.countDocuments()).toBe(1);
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
    const after = await CredentialModel.findOne().select("+passwordHash").lean();
    expect(after!.passwordHash).toBe(before!.passwordHash);
  });

  it("persists failed attempts and blocks even a correct OTP after exhaustion", async () => {
    const response = await register();
    const challengeId = response.body.data.challengeId;
    const otp = sentOtp();
    const wrong = otp === "123456" ? "654321" : "123456";
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await request(app).post("/api/v1/email/verify")
        .send({ challengeId, otp: wrong })).status).toBe(400);
    }
    expect((await request(app).post("/api/v1/email/verify")
      .send({ challengeId, otp })).status).toBe(400);
    const challenge = await OtpChallengeModel.findById(challengeId)
      .select("+attempts");
    expect(challenge!.attempts).toBe(5);
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_EMAIL_OTP_FAILURE",
    })).toBe(5);
  });

  it("rejects expired codes independently of cleanup", async () => {
    const response = await register();
    const challengeId = response.body.data.challengeId;
    await OtpChallengeModel.updateOne({ _id: challengeId }, {
      $set: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await request(app).post("/api/v1/email/verify")
      .send({ challengeId, otp: sentOtp() })).status).toBe(400);
  });

  it("enforces resend cooldown and makes old challenges unusable", async () => {
    const first = await register();
    const oldOtp = sentOtp();
    await request(app).post("/api/v1/email/resend").send({ email });
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
    await allowResend();
    const second = await request(app).post("/api/v1/email/resend").send({ email });
    expect(second.status).toBe(202);
    await drainEmails();
    expect(external.sendOtp).toHaveBeenCalledTimes(2);
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: first.body.data.challengeId, otp: oldOtp,
    })).status).toBe(400);
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: second.body.data.challengeId, otp: sentOtp(),
    })).status).toBe(200);
  });

  it("queues failed deliveries without changing the public registration response", async () => {
    external.sendOtp.mockRejectedValueOnce(new Error("SMTP failure"));
    const response = await register();
    expect(response.status).toBe(202);
    expect(await AuthUserModel.findOne()).toMatchObject({
      status: "PENDING_VERIFICATION", isEmailVerified: false,
    });
    expect(await OtpChallengeModel.countDocuments({
      consumedAt: { $exists: false },
    })).toBe(1);
    await allowResend();
    const resent = await request(app).post("/api/v1/email/resend").send({ email });
    expect(resent.status).toBe(202);
    await drainEmails();
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: resent.body.data.challengeId, otp: sentOtp(),
    })).status).toBe(200);
  });

  it("rolls back every account write if audit persistence fails", async () => {
    vi.spyOn(SecurityEventModel, "create")
      .mockRejectedValueOnce(new Error("Injected database failure"));
    expect((await register()).status).toBe(503);
    for (const model of [
      AuthUserModel, CredentialModel, PasswordHistoryModel, OtpChallengeModel,
    ]) expect(await model.countDocuments()).toBe(0);
    expect(external.sendOtp).not.toHaveBeenCalled();
  });

  it("permits only one successful concurrent verification", async () => {
    const response = await register();
    const body = { challengeId: response.body.data.challengeId, otp: sentOtp() };
    const results = await Promise.all([
      request(app).post("/api/v1/email/verify").send(body),
      request(app).post("/api/v1/email/verify").send(body),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_EMAIL_VERIFIED",
    })).toBe(1);
  });

  it("serializes concurrent resends", async () => {
    await register();
    await allowResend();
    const results = await Promise.all([
      request(app).post("/api/v1/email/resend").send({ email }),
      request(app).post("/api/v1/email/resend").send({ email }),
    ]);
    expect(results.map((result) => result.status)).toEqual([202, 202]);
    await drainEmails();
    expect(external.sendOtp).toHaveBeenCalledTimes(2);
    expect(await OtpChallengeModel.countDocuments({
      consumedAt: { $exists: false },
    })).toBe(1);
  });

  it("creates only one identity for concurrent duplicate registrations", async () => {
    const results = await Promise.all([register(), register()]);
    expect(results.map((result) => result.status)).toEqual([202, 202]);
    expect(await AuthUserModel.countDocuments()).toBe(1);
    expect(await CredentialModel.countDocuments()).toBe(1);
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
  });

  it("rejects malformed and weak requests before external screening", async () => {
    for (const body of [
      { email: "invalid", password },
      { email, password: "x".repeat(129) },
      { email, password, status: "ACTIVE" },
      { email, password: "short" },
    ]) expect((await request(app).post("/api/v1/auth/register").send(body)).status)
      .toBe(400);
    expect(external.checkBreachedPassword).not.toHaveBeenCalled();
    expect(await AuthUserModel.countDocuments()).toBe(0);
  });

  it("prevents registration with compromised passwords", async () => {
    external.checkBreachedPassword.mockResolvedValue({
      checked: true, breached: true, occurrenceCount: 100,
    });
    expect((await register()).body.error.code).toBe("PASSWORD_COMPROMISED");
    expect(await AuthUserModel.countDocuments()).toBe(0);
  });

  it("limits source requests and records a safe rate-limit event", async () => {
    for (let i = 0; i < 10; i += 1) {
      expect((await request(app).post("/api/v1/email/resend")
        .send({ email })).status).toBe(202);
    }
    const limited = await request(app).post("/api/v1/email/resend").send({ email });
    expect(limited.status).toBe(429);
    expect(limited.headers["retry-after"]).toBeDefined();
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_RATE_LIMITED",
    })).toBe(1);
    expect(JSON.stringify(await AbuseBucketModel.find().lean())).not.toContain(email);
  });

  it("does not let anonymous resend requests consume a future user's issuance quota", async () => {
    for (let i = 0; i < 6; i += 1) {
      expect((await request(app).post("/api/v1/email/resend").send({ email })).status).toBe(202);
    }
    expect((await register()).status).toBe(202);
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
  });

  it("caps actual verification jobs while keeping quota responses generic", async () => {
    await register();
    for (let i = 0; i < 6; i += 1) {
      await allowResend();
      const response = await request(app).post("/api/v1/email/resend").send({ email });
      expect(response.status).toBe(202);
    }
    expect(await EmailOutboxModel.countDocuments()).toBe(5);
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
  });

  it("does not activate suspended accounts or reveal unknown accounts on resend", async () => {
    const response = await register();
    await AuthUserModel.updateMany({}, { $set: { status: "SUSPENDED" } });
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: response.body.data.challengeId, otp: sentOtp(),
    })).status).toBe(400);
    const unknown = await request(app).post("/api/v1/email/resend")
      .send({ email: "unknown@example.com" });
    expect(unknown.status).toBe(202);
    expect(external.sendOtp).toHaveBeenCalledTimes(1);
  });
});
