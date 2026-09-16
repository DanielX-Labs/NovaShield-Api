import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import request from "supertest";
import {
  afterAll, beforeAll, beforeEach, describe, expect, it, vi,
} from "vitest";

// No private .env is loaded. Only SMTP and HIBP are replaced by test doubles.
vi.mock("../../src/config/env.js", async () => ({
  env: { ...(await import("../helpers/testEnv.js")).testEnv },
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
import { runRetention } from "../../src/services/security/retention.service.js";
import { env } from "../../src/config/env.js";
import { EmailOutboxModel } from "../../src/models/EmailOutbox.model.js";
import { processOneEmail } from "../../src/services/email/emailOutbox.service.js";
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
  hookTimeout: process.env.NOVASHIELD_TEST_MONGODB_URI ? 60_000 : 10_000,
});
const email = "customer@example.com";
const password = "Orbit-Cedar!Lantern-47";
const models = [
  EmailOutboxModel, AuthAttemptModel, AuthUserModel, CredentialModel, OtpChallengeModel,
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
    serverSelectionTimeoutMS: process.env.NOVASHIELD_TEST_MONGODB_URI ? 30_000 : 10_000,
  });
  await Promise.all(models.map(model => model.init()));
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
  await Promise.all(models.map(model => model.collection.deleteMany({})));
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

async function drainEmails() {
  // Bound each drain so a failed provider cannot spin or bypass backoff.
  for (let index = 0; index < 10 && await processOneEmail(); index += 1) { /* next due job */ }
}
async function register(address = email) {
  const result = await request(app).post("/api/v1/auth/register").send({ email: address, password });
  await drainEmails();
  return result;
}

function sentOtp(): string {
  return external.sendOtp.mock.calls.at(-1)?.[1] as string;
}

async function allowResend() {
  await AuthUserModel.updateMany({}, {
    $set: { verificationOtpIssuedAt: new Date(Date.now() - 61_000) },
  });
}

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


// Password lifecycle tests use real transactions; outbound email and HIBP stay mocked.
const replacementPassword = "Meadow!Quartz-Harbor-82";
const thirdPassword = "Velvet!Comet-Pebble-63";
async function change(access: string, currentPassword = password, newPassword = replacementPassword) {
  const result = await request(app).post("/api/v1/password/change")
    .set("Authorization", `Bearer ${access}`).send({ currentPassword, newPassword });
  await drainEmails();
  return result;
}
async function requestReset(address = email) {
  const result = await request(app).post("/api/v1/password/reset/request").send({ email: address });
  await drainEmails();
  return result;
}
function resetCode(): string {
  return external.sendResetOtp.mock.calls.at(-1)?.[1] as string;
}
async function confirmReset(otp = resetCode(), newPassword = replacementPassword) {
  const challengeId = external.sendResetOtp.mock.calls.at(-1)?.[3]
    ?? "000000000000000000000000";
  const result = await request(app).post("/api/v1/password/reset/confirm")
    .send({ email, challengeId, otp, newPassword });
  await drainEmails();
  return result;
}
export {
  mongoose,
  randomUUID,
  MongoMemoryReplSet,
  request,
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  external,
  AuthAttemptModel,
  runRetention,
  env,
  EmailOutboxModel,
  processOneEmail,
  app,
  AuthUserModel,
  CredentialModel,
  OtpChallengeModel,
  PasswordHistoryModel,
  SecurityEventModel,
  AbuseBucketModel,
  verifyPassword,
  hashPassword,
  SessionModel,
  RefreshTokenModel,
  verifyAccessToken,
  hashRefreshToken,
  dummyPassword,
  replica,
  testDatabaseName,
  email,
  password,
  models,
  loginFixtureHash,
  drainEmails,
  register,
  sentOtp,
  allowResend,
  seedActiveUser,
  login,
  refreshCookie,
  refresh,
  sessions,
  replacementPassword,
  thirdPassword,
  change,
  requestReset,
  resetCode,
  confirmReset
};
