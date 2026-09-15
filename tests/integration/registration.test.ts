import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import request from "supertest";
import {
  afterAll, beforeAll, beforeEach, describe, expect, it, vi,
} from "vitest";

// No private .env is loaded. Only SMTP and HIBP are replaced by test doubles.
vi.mock("../../src/config/env.js", () => ({
  env: {
    NODE_ENV: "test",
    APP_NAME: "NovaShield-test",
    EXPENSEHUB_ORIGIN: "http://localhost:3000",
    AUTH_PEPPER: "integration-test-pepper-not-a-production-secret",
    IP_HASH_SECRET: "integration-network-secret-not-for-production",
    JWT_ACCESS_SECRET: "integration-jwt-secret-not-for-production",
    ACCESS_TOKEN_TTL_MINUTES: 15,
    REFRESH_TOKEN_TTL_DAYS: 7,
    REFRESH_COOKIE_NAME: "novashield_refresh",
    COOKIE_SECURE: false,
    COOKIE_SAME_SITE: "lax",
    LOGIN_WINDOW_MINUTES: 15,
    LOGIN_IP_LIMIT: 5,
    PASSWORD_MIN_LENGTH: 15,
    PASSWORD_MAX_LENGTH: 128,
    ARGON2_MEMORY_COST: 19456,
    ARGON2_TIME_COST: 2,
    ARGON2_PARALLELISM: 1,
    PASSWORD_HISTORY_LIMIT: 5,
    BREACHED_PASSWORD_FAIL_MODE: "closed",
    OTP_TTL_MINUTES: 10,
    OTP_MAX_ATTEMPTS: 5,
    OTP_RESEND_COOLDOWN_SECONDS: 60,
  },
}));
const external = vi.hoisted(() => ({
  sendOtp: vi.fn(),
  checkBreachedPassword: vi.fn(),
}));
vi.mock("../../src/services/email/email.service.js", () => ({
  sendVerificationOtpEmail: external.sendOtp,
}));
vi.mock("../../src/services/password/breachedPassword.service.js", () => ({
  checkBreachedPassword: external.checkBreachedPassword,
}));
// Keep routine HTTP logs out of the test report; production logging is unchanged.
vi.mock("../../src/config/logger.js", async () => {
  const { default: pino } = await import("pino");
  return { logger: pino({ level: "silent" }) };
});

import { app } from "../../src/app.js";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { OtpChallengeModel } from "../../src/models/OtpChallenge.model.js";
import { PasswordHistoryModel } from "../../src/models/PasswordHistory.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { AbuseBucketModel } from "../../src/models/AbuseBucket.model.js";
import { verifyPassword } from "../../src/services/password/passwordHash.service.js";
import { hashPassword } from "../../src/services/password/passwordHash.service.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { verifyAccessToken } from "../../src/services/session/accessToken.service.js";
import { hashRefreshToken } from "../../src/services/session/refreshTokenCrypto.service.js";
import * as dummyPassword from "../../src/services/password/dummyPassword.service.js";

let replica: MongoMemoryReplSet | undefined;
const testDatabaseName = "ns_it_" + randomUUID().replaceAll("-", "");
// Remote replica sets need a larger per-test budget than local unit tests.
vi.setConfig({ testTimeout: 30_000 });
const email = "customer@example.com";
const password = "Orbit-Cedar!Lantern-47";
const models = [
  AuthUserModel, CredentialModel, OtpChallengeModel,
  PasswordHistoryModel, SecurityEventModel, AbuseBucketModel,
  SessionModel, RefreshTokenModel,
];

let loginFixtureHash: string;

beforeAll(async () => {
  // Isolated ephemeral replica set exercises real transactions and unique indexes.
  // An explicit test-runner option can reuse a server, never its application DB.
  let uri = process.env.NOVASHIELD_TEST_MONGODB_URI;
  if (!uri) {
    replica = await MongoMemoryReplSet.create({
      binary: { downloadDir: "node_modules/.cache/mongodb-memory-server" },
      replSet: { count: 1, storageEngine: "wiredTiger" },
    });
    uri = replica.getUri();
  }
  await mongoose.connect(uri, {
    dbName: testDatabaseName,
    serverSelectionTimeoutMS: 10_000,
  });
  for (const model of models) await model.init();
  await dummyPassword.initializeDummyPasswordHash();
  loginFixtureHash = await hashPassword(password);
}, 180_000);

beforeEach(async () => {
  vi.restoreAllMocks();
  external.sendOtp.mockReset().mockResolvedValue(undefined);
  external.checkBreachedPassword.mockReset().mockResolvedValue({
    checked: true, breached: false, occurrenceCount: 0,
  });
  // Deletes affect only this suite's isolated database.
  for (const model of models) await model.collection.deleteMany({});
});

afterAll(async () => {
  // Guard cleanup against accidentally targeting an application database.
  try {
    if (mongoose.connection.db?.databaseName === testDatabaseName) {
      await mongoose.connection.db.dropDatabase();
    }
  } finally {
    await mongoose.disconnect();
    if (replica) await replica.stop();
  }
}, 30_000);

async function register(address = email) {
  return request(app).post("/api/v1/auth/register")
    .send({ email: address, password });
}

function sentOtp(): string {
  return external.sendOtp.mock.calls.at(-1)?.[1] as string;
}

async function allowResend() {
  await AuthUserModel.updateMany({}, {
    $set: { verificationOtpIssuedAt: new Date(Date.now() - 61_000) },
  });
}

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
  it("creates pending identity, hashes, history and audit records then activates once", async () => {
    const response = await register("  CUSTOMER@example.com  ");
    expect(response.status).toBe(202);
    const challengeId = response.body.data.challengeId;
    const user = await AuthUserModel.findOne({ emailNormalized: email }).lean();
    expect(user).toMatchObject({
      status: "PENDING_VERIFICATION", isEmailVerified: false,
    });
    const credential = await CredentialModel.findOne({ userId: user!._id })
      .select("+passwordHash").lean();
    expect(credential!.passwordHash).toMatch(/^\$argon2id\$/u);
    expect(await verifyPassword(credential!.passwordHash, password)).toBe(true);
    expect(await PasswordHistoryModel.countDocuments()).toBe(1);
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
    expect(external.sendOtp).toHaveBeenCalledTimes(2);
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: first.body.data.challengeId, otp: oldOtp,
    })).status).toBe(400);
    expect((await request(app).post("/api/v1/email/verify").send({
      challengeId: second.body.data.challengeId, otp: sentOtp(),
    })).status).toBe(200);
  });

  it("invalidates failed deliveries while retaining recoverable pending accounts", async () => {
    external.sendOtp.mockRejectedValueOnce(new Error("SMTP failure"));
    const response = await register();
    expect(response.status).toBe(503);
    expect(response.body.error.code).toBe("EMAIL_DELIVERY_UNAVAILABLE");
    expect(await AuthUserModel.findOne()).toMatchObject({
      status: "PENDING_VERIFICATION", isEmailVerified: false,
    });
    expect(await OtpChallengeModel.countDocuments({
      consumedAt: { $exists: false },
    })).toBe(0);
    await allowResend();
    const resent = await request(app).post("/api/v1/email/resend").send({ email });
    expect(resent.status).toBe(202);
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

  it("limits email requests and records a safe rate-limit event", async () => {
    for (let i = 0; i < 5; i += 1) {
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

// Login uses the same isolated database and cleanup as the registration tests above.
async function seedActiveUser() {
  const user = await AuthUserModel.create({
    email, emailNormalized: email, status: "ACTIVE", isEmailVerified: true,
  });
  await CredentialModel.create({ userId: user._id, passwordHash: loginFixtureHash });
  return user;
}

function login(address = email, candidate = password) {
  return request(app).post("/api/v1/auth/login")
    .send({ email: address, password: candidate });
}

describe("Login and session creation", () => {
  it("logs in after registration and verification, exposing refresh only in a cookie", async () => {
    const registration = await register();
    await request(app).post("/api/v1/email/verify").send({
      challengeId: registration.body.data.challengeId, otp: sentOtp(),
    });
    const response = await request(app).post("/api/v1/auth/login")
      .set("User-Agent", "NovaShield integration test")
      .send({ email: " CUSTOMER@example.com ", password });
    expect(response.status).toBe(200);
    expect(response.body.data.refreshToken).toBeUndefined();
    expect(response.body.data.expiresIn).toBe(900);
    const claims = verifyAccessToken(response.body.data.accessToken);
    expect(claims).toMatchObject({
      sub: response.body.data.userId,
      sid: response.body.data.sessionId,
      ver: 1,
      type: "access",
    });

    const cookies = response.headers["set-cookie"] as unknown as string[];
    expect(cookies).toHaveLength(1);
    const cookie = cookies[0]!;
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Path=/api/v1/auth");
    expect(cookie).toContain("SameSite=Lax");
    expect(response.headers["cache-control"]).toBe("no-store");
    const rawToken = decodeURIComponent(cookie.split(";")[0]!.split("=")[1]!);
    const session = await SessionModel.findOne().select("+ipHash").lean();
    const refresh = await RefreshTokenModel.findOne().select("+tokenHash").lean();
    expect(session).toMatchObject({
      sessionId: response.body.data.sessionId,
      userAgent: "NovaShield integration test",
    });
    expect(session!.ipHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(refresh!.sessionId.toString()).toBe(session!._id.toString());
    expect(refresh!._id.toString()).toBe(rawToken.split(".")[0]);
    expect(refresh!.tokenHash).toBe(hashRefreshToken(rawToken));
    expect(refresh!.familyId).toMatch(/^[a-f0-9-]{36}$/u);
    expect(refresh!.expiresAt.getTime()).toBe(session!.expiresAt.getTime());
    const events = await SecurityEventModel.find({ eventType: "AUTH_LOGIN_SUCCESS" }).lean();
    expect(events).toHaveLength(1);
    expect(events[0]!.sessionId).toBe(session!.sessionId);

    // Inspect raw MongoDB documents, not just projections that hide sensitive fields.
    for (const model of models) {
      const stored = JSON.stringify(await model.collection.find({}).toArray());
      for (const sensitive of [
        password, rawToken,
        "integration-test-pepper-not-a-production-secret",
        "integration-network-secret-not-for-production",
        "integration-jwt-secret-not-for-production",
      ]) expect(stored).not.toContain(sensitive);
    }
  });

  it("returns the same credential error for wrong passwords and unknown email", async () => {
    const user = await seedActiveUser();
    const wrong = await login(email, "Wrong-Cedar!Lantern-47");
    const dummy = vi.spyOn(dummyPassword, "performDummyPasswordVerification");
    const unknown = await login("unknown@example.com");
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error).toEqual(unknown.body.error);
    expect(dummy).toHaveBeenCalledWith(password);
    expect(await AuthUserModel.findById(user._id).select("+failedLoginCount"))
      .toMatchObject({ failedLoginCount: 1 });
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_FAILURE" }))
      .toBe(2);
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(wrong.headers["set-cookie"]).toBeUndefined();
  });

  it("performs dummy verification when credentials are missing", async () => {
    await AuthUserModel.create({ email, emailNormalized: email });
    const dummy = vi.spyOn(dummyPassword, "performDummyPasswordVerification");
    expect((await login()).body.error.code).toBe("INVALID_CREDENTIALS");
    expect(dummy).toHaveBeenCalledWith(password);
    expect(await SessionModel.countDocuments()).toBe(0);
  });

  it.each(["PENDING_VERIFICATION", "SUSPENDED", "DISABLED"])(
    "rejects %s accounts after password verification",
    async (status) => {
      await seedActiveUser();
      await AuthUserModel.updateMany({}, { $set: {
        status, isEmailVerified: status !== "PENDING_VERIFICATION",
      } });
      const response = await login();
      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe("ACCOUNT_NOT_AVAILABLE");
      expect(await SessionModel.countDocuments()).toBe(0);
      expect(await RefreshTokenModel.countDocuments()).toBe(0);
      expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_FAILURE" }))
        .toBe(1);
    },
  );

  it("resets failures on success and refunds successful rate-limit reservations", async () => {
    const user = await seedActiveUser();
    await login(email, "Wrong-Cedar!Lantern-47");
    expect((await login()).status).toBe(200);
    const after = await AuthUserModel.findById(user._id)
      .select("+failedLoginCount +lastFailedLoginAt").lean();
    expect(after!.failedLoginCount).toBe(0);
    expect(after!.lastSuccessfulLoginAt).toBeInstanceOf(Date);
    expect(after!.lastFailedLoginAt).toBeInstanceOf(Date);
    await expect.poll(async () => {
      const buckets = await AbuseBucketModel.find().lean();
      return buckets.reduce((sum, bucket) => sum + bucket.count, 0);
    }).toBe(1);
  });

  it("rate limits repeated failures without permanently locking the account", async () => {
    const user = await seedActiveUser();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await login(email, "Wrong-Cedar!Lantern-47")).status).toBe(401);
    }
    const response = await login();
    expect(response.status).toBe(429);
    expect(response.headers["retry-after"]).toBeDefined();
    expect(await AuthUserModel.findById(user._id)).toMatchObject({ status: "ACTIVE" });
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_RATE_LIMITED" }))
      .toBe(1);
  });

  it("preserves concurrent failure increments", async () => {
    const user = await seedActiveUser();
    const results = await Promise.all([
      login(email, "Wrong-Cedar!Lantern-47"),
      login(email, "Wrong-Cedar!Lantern-47"),
      login(email, "Wrong-Cedar!Lantern-47"),
    ]);
    expect(results.map((result) => result.status)).toEqual([401, 401, 401]);
    expect(await AuthUserModel.findById(user._id).select("+failedLoginCount"))
      .toMatchObject({ failedLoginCount: 3 });
  });

  it("rolls back session and login state when refresh-token storage fails", async () => {
    const user = await seedActiveUser();
    vi.spyOn(RefreshTokenModel, "create")
      .mockRejectedValueOnce(new Error("Injected storage failure"));
    const response = await login();
    expect(response.status).toBe(503);
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(0);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_SUCCESS" }))
      .toBe(0);
    expect((await AuthUserModel.findById(user._id))!.lastSuccessfulLoginAt)
      .toBeUndefined();
  });

  it("rolls back session and refresh token when success auditing fails", async () => {
    await seedActiveUser();
    vi.spyOn(SecurityEventModel, "create")
      .mockRejectedValueOnce(new Error("Injected audit failure"));
    expect((await login()).status).toBe(503);
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(0);
  });

  it("rejects excessive input and untrusted browser origins", async () => {
    const excessive = await login(email, "x".repeat(129));
    expect(excessive.status).toBe(400);
    const origin = await request(app).post("/api/v1/auth/login")
      .set("Origin", "https://attacker.example")
      .send({ email, password });
    expect(origin.status).toBe(403);
    expect(origin.body.error.code).toBe("ORIGIN_NOT_ALLOWED");
    expect(await SessionModel.countDocuments()).toBe(0);
  });
});
