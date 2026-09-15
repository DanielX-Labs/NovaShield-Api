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
    AUTH_FAILURE_WINDOW_MINUTES: 15,
    AUTH_ACCOUNT_FAILURE_LIMIT: 8,
    AUTH_IP_FAILURE_LIMIT: 30,
    AUTH_PROGRESSIVE_DELAY_AFTER: 3,
    AUTH_PROGRESSIVE_DELAY_BASE_MS: 500,
    AUTH_PROGRESSIVE_DELAY_MAX_MS: 5000,
    AUTH_SPRAY_ACCOUNT_THRESHOLD: 8,
    AUTH_SUSPICIOUS_SCORE_THRESHOLD: 50,
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
    PASSWORD_RESET_OTP_TTL_MINUTES: 10,
    PASSWORD_RESET_MAX_ATTEMPTS: 5,
    PASSWORD_RESET_REQUEST_WINDOW_MINUTES: 15,
    PASSWORD_RESET_REQUEST_LIMIT: 5,
    OTP_TTL_MINUTES: 10,
    OTP_MAX_ATTEMPTS: 5,
    OTP_RESEND_COOLDOWN_SECONDS: 60,
  },
}));
const external = vi.hoisted(() => ({
  sendOtp: vi.fn(),
  sendResetOtp: vi.fn(),
  sendChanged: vi.fn(),
  checkBreachedPassword: vi.fn(),
}));
vi.mock("../../src/services/email/email.service.js", () => ({
  sendVerificationOtpEmail: external.sendOtp,
  sendPasswordResetOtpEmail: external.sendResetOtp,
  sendPasswordChangedEmail: external.sendChanged,
}));
vi.mock("../../src/services/password/breachedPassword.service.js", () => ({
  checkBreachedPassword: external.checkBreachedPassword,
}));
// Keep routine HTTP logs out of the test report; production logging is unchanged.
vi.mock("../../src/config/logger.js", async () => {
  const { default: pino } = await import("pino");
  return { logger: pino({ level: "silent" }) };
});

import { AuthAttemptModel } from "../../src/models/AuthAttempt.model.js";
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
vi.setConfig({
  testTimeout: process.env.NOVASHIELD_TEST_MONGODB_URI ? 60_000 : 30_000,
});
const email = "customer@example.com";
const password = "Orbit-Cedar!Lantern-47";
const models = [
  AuthAttemptModel, AuthUserModel, CredentialModel, OtpChallengeModel,
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
  external.sendResetOtp.mockReset().mockResolvedValue(undefined);
  external.sendChanged.mockReset().mockResolvedValue(undefined);
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
    expect(credential!.passwordHash).toMatch(/^\$argon2id\$/u);
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

// Keep raw cookies only in test memory to exercise real HTTP parsing.
function refreshCookie(response: { headers: Record<string, unknown> }): string {
  return (response.headers["set-cookie"] as string[])[0]!.split(";")[0]!;
}
function refresh(cookie: string) {
  return request(app).post("/api/v1/auth/refresh").set("Cookie", cookie);
}
function sessions(access: string) {
  return request(app).get("/api/v1/auth/sessions")
    .set("Authorization", "Bearer " + access);
}

describe("Refresh rotation and session lifecycle", () => {
  it("completes registration through rotation, then revokes the family on replay", async () => {
    const registration = await register();
    await request(app).post("/api/v1/email/verify").send({
      challengeId: registration.body.data.challengeId, otp: sentOtp(),
    });
    const initial = await login();
    const r1 = refreshCookie(initial);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    const rotated = await refresh(r1);
    expect(rotated.status).toBe(200);
    expect(rotated.body.data.refreshToken).toBeUndefined();
    const r2 = refreshCookie(rotated);
    expect(r2).not.toBe(r1);
    const tokens = await RefreshTokenModel.find()
      .select("+usedAt +replacedByTokenId +tokenHash").sort({ createdAt: 1 });
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.familyId).toBe(tokens[1]!.familyId);
    expect(tokens[0]!.usedAt).toBeInstanceOf(Date);
    expect(tokens[0]!.replacedByTokenId!.toString()).toBe(tokens[1]!._id.toString());
    expect(tokens[0]!.expiresAt).toEqual(tokens[1]!.expiresAt);
    expect((await sessions(rotated.body.data.accessToken)).status).toBe(200);

    const replay = await refresh(r1);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe("REFRESH_TOKEN_REUSED");
    expect(replay.headers["set-cookie"]?.[0]).toContain("Expires=Thu, 01 Jan 1970");
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await sessions(rotated.body.data.accessToken)).status).toBe(401);
    expect((await refresh(r2)).status).toBe(401);
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_REFRESH_REUSED", severity: "HIGH",
    })).toBe(1);
    const stored = JSON.stringify(await RefreshTokenModel.collection.find({}).toArray());
    expect(stored).not.toContain(decodeURIComponent(r1.split("=")[1]!));
    expect(stored).not.toContain(decodeURIComponent(r2.split("=")[1]!));
  });

  it("permits only one concurrent rotation, then treats the loser as replay", async () => {
    await seedActiveUser();
    const initial = await login();
    const r1 = refreshCookie(initial);
    const results = await Promise.all([refresh(r1), refresh(r1)]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 401]);
    expect(await RefreshTokenModel.countDocuments()).toBe(2);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    const winner = results.find((result) => result.status === 200)!;
    expect((await refresh(refreshCookie(winner))).status).toBe(401);
  });

  it("does not revoke a valid family when an attacker supplies a wrong secret", async () => {
    await seedActiveUser();
    const initial = await login();
    const r1 = refreshCookie(initial);
    const rotated = await refresh(r1);
    const raw = decodeURIComponent(r1.split("=")[1]!);
    const wrong = raw.slice(0, -1) + (raw.endsWith("A") ? "B" : "A");
    const result = await refresh("novashield_refresh=" + wrong);
    expect(result.status).toBe(401);
    expect(result.body.error.code).toBe("INVALID_REFRESH_TOKEN");
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    expect((await refresh(refreshCookie(rotated))).status).toBe(200);
  });

  it("rejects missing, malformed, unknown and expired refresh tokens", async () => {
    expect((await request(app).post("/api/v1/auth/refresh")).status).toBe(401);
    expect((await refresh("novashield_refresh=invalid")).status).toBe(401);
    expect((await refresh("novashield_refresh=" + "a".repeat(24) + "." + "A".repeat(64)))
      .status).toBe(401);
    await seedActiveUser();
    const initial = await login();
    await RefreshTokenModel.updateMany({}, {
      $set: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await refresh(refreshCookie(initial))).body.error.code)
      .toBe("REFRESH_TOKEN_EXPIRED");
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
  });

  it("requires an allowed browser origin before touching a refresh token", async () => {
    await seedActiveUser();
    const initial = await login();
    const blocked = await request(app).post("/api/v1/auth/refresh")
      .set("Cookie", refreshCookie(initial))
      .set("Origin", "https://attacker.example");
    expect(blocked.status).toBe(403);
    expect(blocked.headers["set-cookie"]).toBeUndefined();
    expect(await RefreshTokenModel.countDocuments({ usedAt: { $exists: true } })).toBe(0);
  });

  it("lists only owned active sessions and clears the cookie when revoking current", async () => {
    await seedActiveUser();
    const first = await login();
    const second = await login();
    const listed = await sessions(first.body.data.accessToken);
    expect(listed.body.data.sessions).toHaveLength(2);
    expect(listed.body.data.sessions.filter((entry: { current: boolean }) => entry.current))
      .toHaveLength(1);
    for (const entry of listed.body.data.sessions) {
      expect(entry._id).toBeUndefined();
      expect(entry.userId).toBeUndefined();
      expect(entry.ipHash).toBeUndefined();
    }
    const revokedOther = await request(app)
      .delete("/api/v1/auth/sessions/" + second.body.data.sessionId)
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(revokedOther.status).toBe(204);
    expect(revokedOther.headers["set-cookie"]).toBeUndefined();
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await sessions(first.body.data.accessToken)).body.data.sessions).toHaveLength(1);
    const revokedSelf = await request(app)
      .delete("/api/v1/auth/sessions/" + first.body.data.sessionId)
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(revokedSelf.status).toBe(204);
    expect(revokedSelf.headers["set-cookie"]).toBeDefined();
    expect((await refresh(refreshCookie(first))).status).toBe(401);
  });

  it("rejects cross-user session revocation without affecting the owner", async () => {
    await seedActiveUser();
    const owner = await login();
    const other = await AuthUserModel.create({
      email: "other@example.com", emailNormalized: "other@example.com",
      status: "ACTIVE", isEmailVerified: true,
    });
    await CredentialModel.create({ userId: other._id, passwordHash: loginFixtureHash });
    const stranger = await login("other@example.com");
    const response = await request(app)
      .delete("/api/v1/auth/sessions/" + owner.body.data.sessionId)
      .set("Authorization", "Bearer " + stranger.body.data.accessToken);
    expect(response.status).toBe(404);
    expect((await sessions(owner.body.data.accessToken)).status).toBe(200);
    expect((await sessions(stranger.body.data.accessToken)).body.data.sessions).toHaveLength(1);
  });

  it("revokes all owned sessions and cookies", async () => {
    await seedActiveUser();
    const first = await login();
    const second = await login();
    const result = await request(app).delete("/api/v1/auth/sessions")
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(result.status).toBe(204);
    expect(result.headers["set-cookie"]).toBeDefined();
    expect((await sessions(first.body.data.accessToken)).status).toBe(401);
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(second))).status).toBe(401);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
  });

  it("logs out server-side and rejects both old access and refresh tokens", async () => {
    await seedActiveUser();
    const initial = await login();
    const result = await request(app).post("/api/v1/auth/logout")
      .set("Authorization", "Bearer " + initial.body.data.accessToken);
    expect(result.status).toBe(204);
    expect(result.headers["set-cookie"]?.[0]).toContain("HttpOnly");
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).status).toBe(401);
  });

  it("rejects disabled accounts using still-valid JWTs", async () => {
    await seedActiveUser();
    const initial = await login();
    await AuthUserModel.updateMany({}, { $set: { status: "DISABLED" } });
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).body.error.code).toBe("INVALID_SESSION");
    expect(await SessionModel.countDocuments({ revokedAt: { $exists: true } })).toBe(1);
  });

  it("does not let an old refresh token adopt a newer credential version", async () => {
    await seedActiveUser();
    const initial = await login();
    await CredentialModel.updateMany({}, { $inc: { passwordVersion: 1 } });
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).status).toBe(401);
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
  });

  it("rolls back consumption if replacement storage fails and permits retry", async () => {
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(RefreshTokenModel, "create")
      .mockRejectedValueOnce(new Error("Injected replacement failure"));
    const result = await refresh(refreshCookie(initial));
    expect(result.status).toBe(503);
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect(await RefreshTokenModel.countDocuments({ usedAt: { $exists: true } })).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
    expect((await refresh(refreshCookie(initial))).status).toBe(200);
  });

  it("rolls back logout if its audit event fails", async () => {
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(SecurityEventModel, "create")
      .mockRejectedValueOnce(new Error("Injected audit failure"));
    const result = await request(app).post("/api/v1/auth/logout")
      .set("Authorization", "Bearer " + initial.body.data.accessToken);
    expect(result.status).toBe(503);
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    expect((await refresh(refreshCookie(initial))).status).toBe(200);
  });

  it("keeps logout effective when it races a rotation", async () => {
    await seedActiveUser();
    const initial = await login();
    const results = await Promise.all([
      refresh(refreshCookie(initial)),
      request(app).post("/api/v1/auth/logout")
        .set("Authorization", "Bearer " + initial.body.data.accessToken),
    ]);
    expect(results[1]!.status).toBe(204);
    expect([200, 401]).toContain(results[0]!.status);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
  });

  it("rate limits refresh and distinguishes missing authentication from outages", async () => {
    await request(app).post("/api/v1/auth/refresh");
    await AbuseBucketModel.updateMany({ _id: /^refresh-ip:/ }, { $set: { count: 60 } });
    expect((await request(app).post("/api/v1/auth/refresh")).status).toBe(429);
    expect((await request(app).get("/api/v1/auth/sessions")).body.error.code)
      .toBe("AUTHENTICATION_REQUIRED");
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(SessionModel, "findOne").mockRejectedValueOnce(new Error("Database failure"));
    expect((await sessions(initial.body.data.accessToken)).status).toBe(503);
  });
});


// Password lifecycle tests use real transactions; outbound email and HIBP stay mocked.
const replacementPassword = "Meadow!Quartz-Harbor-82";
const thirdPassword = "Velvet!Comet-Pebble-63";
function change(access: string, currentPassword = password, newPassword = replacementPassword) {
  return request(app).post("/api/v1/password/change")
    .set("Authorization", `Bearer ${access}`).send({ currentPassword, newPassword });
}
function requestReset(address = email) {
  return request(app).post("/api/v1/password/reset/request").send({ email: address });
}
function resetCode(): string {
  return external.sendResetOtp.mock.calls.at(-1)?.[1] as string;
}
function confirmReset(otp = resetCode(), newPassword = replacementPassword) {
  return request(app).post("/api/v1/password/reset/confirm")
    .send({ email, otp, newPassword });
}

describe("Password lifecycle", () => {
  it("changes credentials, archives only the old hash and revokes all sessions", async () => {
    const user = await seedActiveUser();
    const first = await login();
    const second = await login();
    const result = await change(first.body.data.accessToken);
    expect(result.status).toBe(200);
    expect(String(result.headers["set-cookie"])).toContain("Expires=Thu, 01 Jan 1970");
    const credential = await CredentialModel.findOne({ userId: user._id }).select("+passwordHash");
    expect(credential?.passwordVersion).toBe(2);
    expect(await verifyPassword(credential!.passwordHash, replacementPassword)).toBe(true);
    const history = await PasswordHistoryModel.find().select("+passwordHash");
    expect(history.map((entry) => entry.passwordHash)).toEqual([loginFixtureHash]);
    expect((await AuthUserModel.findById(user._id))?.passwordChangedAt).toBeInstanceOf(Date);
    expect(await SessionModel.countDocuments({ revokedAt: { $exists: false } })).toBe(0);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } })).toBe(0);
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(first))).status).toBe(401);
    expect((await login()).status).toBe(401);
    expect((await login(email, replacementPassword)).status).toBe(200);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_CHANGED" })).toBe(1);
    expect(external.sendChanged).toHaveBeenCalledWith(email);
  });

  it("rejects wrong current passwords, weak replacements and the current password", async () => {
    await seedActiveUser();
    const access = (await login()).body.data.accessToken;
    expect((await change(access, "incorrect-password")).body.error.code).toBe("CURRENT_PASSWORD_INVALID");
    expect((await change(access, password, "short")).body.error.code).toBe("PASSWORD_POLICY_VIOLATION");
    expect((await change(access, password, password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
    expect(await PasswordHistoryModel.countDocuments()).toBe(0);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
    expect(external.sendChanged).not.toHaveBeenCalled();
  });

  it("keeps A and B after A to B to C, and rejects returning to A", async () => {
    await seedActiveUser();
    // Simulate a legacy registration that seeded its current hash in history.
    const credential = await CredentialModel.findOne();
    await PasswordHistoryModel.create({ userId: credential!.userId, passwordHash: loginFixtureHash });
    expect((await change((await login()).body.data.accessToken)).status).toBe(200);
    const accessB = (await login(email, replacementPassword)).body.data.accessToken;
    expect((await change(accessB, replacementPassword, thirdPassword)).status).toBe(200);
    const history = await PasswordHistoryModel.find().select("+passwordHash");
    expect(history).toHaveLength(2);
    expect(await Promise.all(history.map((entry) => verifyPassword(entry.passwordHash, thirdPassword))))
      .toEqual([false, false]);
    const accessC = (await login(email, thirdPassword)).body.data.accessToken;
    expect((await change(accessC, thirdPassword, password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
  });

  it("returns generic reset responses for unknown and unavailable accounts", async () => {
    const unknown = await requestReset();
    await seedActiveUser();
    await AuthUserModel.updateMany({}, { $set: { status: "DISABLED" } });
    const disabled = await requestReset();
    expect(unknown.status).toBe(202);
    expect(disabled.status).toBe(202);
    expect(disabled.body.message).toBe(unknown.body.message);
    expect(external.sendResetOtp).not.toHaveBeenCalled();
  });

  it("stores a bound HMAC challenge, enforces cooldown and never stores plaintext", async () => {
    await seedActiveUser();
    expect((await requestReset()).status).toBe(202);
    expect((await requestReset()).status).toBe(202);
    expect(external.sendResetOtp).toHaveBeenCalledTimes(1);
    const challenge = await OtpChallengeModel.findOne().select("+otpHash +credentialVersion +maxAttempts");
    expect(challenge?.purpose).toBe("PASSWORD_RESET");
    expect(challenge?.credentialVersion).toBe(1);
    expect(challenge?.maxAttempts).toBe(5);
    expect(challenge?.otpHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(challenge?.otpHash).not.toBe(resetCode());
    expect(challenge!.expiresAt.getTime() - challenge!.createdAt.getTime()).toBeGreaterThan(590_000);
    const stored = JSON.stringify(await OtpChallengeModel.collection.findOne({}));
    expect(stored).not.toContain(`"${resetCode()}"`);
    expect(stored).not.toContain(password);
  });

  it("resets once, revokes old tokens and accepts only the new password", async () => {
    await seedActiveUser();
    const loggedIn = await login();
    await requestReset();
    const otp = resetCode();
    expect((await confirmReset(otp)).status).toBe(200);
    expect((await confirmReset(otp)).body.error.code).toBe("PASSWORD_RESET_INVALID");
    expect((await sessions(loggedIn.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(loggedIn))).status).toBe(401);
    expect((await login()).status).toBe(401);
    expect((await login(email, replacementPassword)).status).toBe(200);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await PasswordHistoryModel.countDocuments()).toBe(1);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_RESET_COMPLETED" })).toBe(1);
  });

  it("does not consume a correct OTP when policy or breach screening rejects", async () => {
    await seedActiveUser();
    await requestReset();
    expect((await confirmReset(resetCode(), "short")).body.error.code).toBe("PASSWORD_POLICY_VIOLATION");
    external.checkBreachedPassword.mockResolvedValueOnce({ checked: true, breached: true, occurrenceCount: 1 });
    expect((await confirmReset()).body.error.code).toBe("PASSWORD_COMPROMISED");
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
    expect((await confirmReset()).status).toBe(200);
  });

  it("checks OTP knowledge before revealing current-password or history feedback", async () => {
    await seedActiveUser();
    await requestReset();
    const wrong = resetCode() === "123456" ? "654321" : "123456";
    expect((await confirmReset(wrong, password)).body.error.code).toBe("PASSWORD_RESET_INVALID");
    expect(external.checkBreachedPassword).not.toHaveBeenCalled();
    expect((await confirmReset(resetCode(), password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_RESET_OTP_FAILURE" })).toBe(1);
  });

  it("persists the OTP attempt limit and rejects even a correct exhausted code", async () => {
    await seedActiveUser();
    await requestReset();
    const wrong = resetCode() === "123456" ? "654321" : "123456";
    for (let index = 0; index < 5; index += 1) {
      expect((await confirmReset(wrong)).status).toBe(400);
    }
    expect((await confirmReset()).body.error.code).toBe("PASSWORD_RESET_INVALID");
    const challenge = await OtpChallengeModel.findOne().select("+attempts");
    expect(challenge?.attempts).toBe(5);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
  });

  it("rejects expired and wrong-purpose challenges", async () => {
    await seedActiveUser();
    await requestReset();
    await OtpChallengeModel.updateMany({}, { $set: { purpose: "EMAIL_VERIFICATION" } });
    expect((await confirmReset()).status).toBe(400);
    await OtpChallengeModel.updateMany({}, {
      $set: { purpose: "PASSWORD_RESET", expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await confirmReset()).status).toBe(400);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
  });

  it("invalidates a reset code when an authenticated password change commits", async () => {
    await seedActiveUser();
    const access = (await login()).body.data.accessToken;
    await requestReset();
    expect((await change(access)).status).toBe(200);
    expect((await confirmReset(resetCode(), thirdPassword)).status).toBe(400);
  });

  it("commits only one concurrent use of a reset code", async () => {
    await seedActiveUser();
    await requestReset();
    const results = await Promise.all([confirmReset(), confirmReset()]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await PasswordHistoryModel.countDocuments()).toBe(1);
    expect(external.sendChanged).toHaveBeenCalledTimes(1);
  });

  it("rolls back credential, history and OTP consumption if the completion audit fails", async () => {
    await seedActiveUser();
    await requestReset();
    const createEvent = SecurityEventModel.create.bind(SecurityEventModel);
    const spy = vi.spyOn(SecurityEventModel, "create").mockImplementation((...args: any[]) => {
      if (args[0]?.[0]?.eventType === "AUTH_PASSWORD_RESET_COMPLETED") {
        return Promise.reject(new Error("test audit unavailable"));
      }
      return (createEvent as any)(...args);
    });
    expect((await confirmReset()).status).toBe(503);
    spy.mockRestore();
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
    expect(await PasswordHistoryModel.countDocuments()).toBe(0);
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
    expect((await confirmReset()).status).toBe(200);
  });

  it("keeps completed changes successful when security notification delivery fails", async () => {
    await seedActiveUser();
    external.sendChanged.mockRejectedValue(new Error("SMTP unavailable"));
    expect((await change((await login()).body.data.accessToken)).status).toBe(200);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_SECURITY_NOTIFICATION_FAILURE" })).toBe(1);
  });

  it("hides reset delivery failure and invalidates the undelivered code", async () => {
    await seedActiveUser();
    external.sendResetOtp.mockRejectedValue(new Error("SMTP unavailable"));
    expect((await requestReset()).status).toBe(202);
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(0);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_EMAIL_DELIVERY_FAILURE" })).toBe(1);
  });

  it("requires authentication, rejects cross-site requests and bounds reset requests", async () => {
    expect((await change("invalid")).status).toBe(401);
    expect((await request(app).post("/api/v1/password/reset/request")
      .set("Origin", "https://attacker.example").send({ email })).status).toBe(403);
    for (let index = 0; index < 4; index += 1) {
      expect((await requestReset()).status).toBe(202);
    }
    expect((await requestReset()).status).toBe(429);
    expect((await request(app).post("/api/v1/password/reset/confirm")
      .send({ email, otp: "<script>", newPassword: replacementPassword })).status).toBe(400);
  });
});
