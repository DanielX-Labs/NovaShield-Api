import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import request from "supertest";
import { beforeAll, afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// Use the same isolated replica-set pattern as the lifecycle integration suite.
vi.mock("../../src/config/env.js", async () => ({
  env: { ...(await import("../helpers/testEnv.js")).testEnv },
}));
const timing = vi.hoisted(() => ({ delay: vi.fn() }));
vi.mock("../../src/utils/delay.js", () => ({ delay: timing.delay }));
vi.mock("../../src/config/logger.js", async () => {
  const { default: pino } = await import("pino");
  return { logger: pino({ level: "silent" }) };
});
import { admitLogin, releaseAdmission } from "../../src/services/security/authAdmission.service.js";
import { app } from "../../src/app.js";
import { initializeAuthStorage } from "../../src/config/authStorage.js";
import { AuthAttemptModel } from "../../src/models/AuthAttempt.model.js";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { loginUser } from "../../src/services/auth/login.service.js";
import { hashPassword } from "../../src/services/password/passwordHash.service.js";
import { initializeDummyPasswordHash } from "../../src/services/password/dummyPassword.service.js";
import { hashAuthIdentifier } from "../../src/services/security/identifierHash.service.js";
import { assessLoginAbuse } from "../../src/services/security/authAbuse.service.js";

const databaseName = "ns_it_" + randomUUID().replaceAll("-", "");
const email = "customer@example.com";
const password = "Orbit-Cedar!Lantern-47";
const ipHash = "protected-test-network";
let replica: MongoMemoryReplSet | undefined;
let passwordHash: string;
vi.setConfig({ testTimeout: 30_000 });
beforeAll(async () => {
  let uri = process.env.NOVASHIELD_TEST_MONGODB_URI;
  if (!uri) {
    replica = await MongoMemoryReplSet.create({
      binary: { downloadDir: "node_modules/.cache/mongodb-memory-server" },
      replSet: { count: 1, storageEngine: "wiredTiger" },
    });
    uri = replica.getUri();
  }
  await mongoose.connect(uri, { dbName: databaseName, serverSelectionTimeoutMS: 10_000 });
  await initializeAuthStorage();
  await initializeDummyPasswordHash();
  passwordHash = await hashPassword(password);
}, 180_000);

beforeEach(async () => {
  vi.restoreAllMocks();
  timing.delay.mockReset().mockResolvedValue(undefined);
  // Clean only collections inside the randomly named test database.
  await Promise.all(Object.values(mongoose.connection.collections)
    .map(collection => collection.deleteMany({})));
});
afterAll(async () => {
  try {
    if (mongoose.connection.db?.databaseName === databaseName) {
      await mongoose.connection.db.dropDatabase();
    }
  } finally {
    await mongoose.disconnect();
    if (replica) await replica.stop();
  }
}, 30_000);

async function seedUser() {
  const user = await AuthUserModel.create({
    email, emailNormalized: email, status: "ACTIVE", isEmailVerified: true,
  });
  await CredentialModel.create({ userId: user._id, passwordHash });
  return user;
}
async function seedFailures(count: number, accounts = 1, address = email) {
  await AuthAttemptModel.insertMany(Array.from({ length: count }, (_, index) => ({
    emailHash: hashAuthIdentifier(accounts === 1 ? address : `target${index % accounts}@example.com`),
    ipHash, outcome: "FAILURE", reason: "INVALID_CREDENTIALS",
  })));
}
function attempt(candidate = password, address = email, network = ipHash) {
  return loginUser({ email: address, password: candidate, ipHash: network, requestId: "security-test" });
}

describe("Local authentication abuse defense", () => {
  it("keeps unknown and incorrect credentials publicly identical", async () => {
    await seedUser();
    const unknown = await request(app).post("/api/v1/auth/login")
      .send({ email: "unknown@example.com", password: "wrong-password" });
    const wrong = await request(app).post("/api/v1/auth/login")
      .send({ email, password: "wrong-password" });
    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(unknown.body.error).toEqual(wrong.body.error);
    const records = await AuthAttemptModel.find().lean();
    expect(records).toHaveLength(2);
    expect(records.every((entry) => entry.outcome === "FAILURE")).toBe(true);
    const stored = JSON.stringify(records);
    expect(stored).not.toContain(email);
    expect(stored).not.toContain("wrong-password");
  });

  it("delays repeated account failures and retains them after successful login", async () => {
    const user = await seedUser();
    await seedFailures(3);
    await AuthUserModel.updateOne({ _id: user._id }, { $set: { failedLoginCount: 3 } });
    await attempt();
    expect(timing.delay).toHaveBeenCalledWith(500);
    expect(await AuthAttemptModel.countDocuments({ outcome: "FAILURE" })).toBe(3);
    expect(await AuthAttemptModel.countDocuments({ outcome: "SUCCESS" })).toBe(1);
    expect((await AuthUserModel.findById(user._id).select("+failedLoginCount"))?.failedLoginCount).toBe(0);
  });

  it("allows a correct password from another IP despite account-wide failures", async () => {
    await seedUser();
    await seedFailures(8);
    await expect(attempt(password, email, "different-network"))
      .resolves.toHaveProperty("accessToken");
    expect(await SessionModel.countDocuments()).toBe(1);
    expect((await AuthUserModel.findOne())?.status).toBe("ACTIVE");
    expect(await AuthAttemptModel.countDocuments({ outcome: "BLOCKED" })).toBe(0);
    expect(await AuthAttemptModel.countDocuments({ outcome: "FAILURE" })).toBe(8);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_RATE_LIMITED" })).toBe(0);
    expect(timing.delay).toHaveBeenCalledWith(5000);
  });

  it("recovers when failures age out even while blocked records remain", async () => {
    await seedUser();
    await seedFailures(30, 10);
    await expect(attempt()).rejects.toMatchObject({ code: "AUTH_RATE_LIMITED" });
    await AuthAttemptModel.collection.updateMany({ outcome: "FAILURE" }, {
      $set: { createdAt: new Date(Date.now() - 16 * 60_000) },
    });
    await expect(attempt()).resolves.toHaveProperty("accessToken");
    expect(await AuthAttemptModel.countDocuments()).toBe(32);
    expect(timing.delay).not.toHaveBeenCalled();
  });

  it("detects spraying and multi-account failures before a successful login", async () => {
    await seedUser();
    await seedFailures(12, 8);
    await attempt();
    const event = await SecurityEventModel.findOne({ eventType: "AUTH_SUSPICIOUS_LOGIN" }).lean();
    expect(event?.severity).toBe("HIGH");
    expect(event?.metadata).toEqual({
      score: 80, reasons: ["POSSIBLE_PASSWORD_SPRAY", "MULTI_ACCOUNT_FAILURE_PATTERN"],
      accountFailures: 0, ipFailures: 12, distinctAccountsFromIp: 8,
    });
    const success = await SecurityEventModel.findOne({ eventType: "AUTH_LOGIN_SUCCESS" }).lean();
    expect(success?.metadata).toEqual(event?.metadata);
    expect(JSON.stringify(event)).not.toContain(email);
    expect(JSON.stringify(event)).not.toContain(password);
    expect(await AuthAttemptModel.countDocuments({ outcome: "FAILURE" })).toBe(12);
  });

  it("refuses an IP threshold and bounds the combined risk score", async () => {
    await seedFailures(30, 10);
    await expect(attempt()).rejects.toMatchObject({ code: "AUTH_RATE_LIMITED" });
    await seedFailures(8);
    const risk = await assessLoginAbuse({ email, ipHash });
    expect(risk.score).toBe(100);
    expect(risk.blocked).toBe(true);
    expect(risk.delayMs).toBe(5000);
  });

  it("records unavailable accounts as failures and never creates sessions", async () => {
    await seedUser();
    await AuthUserModel.updateMany({}, { $set: { status: "DISABLED" } });
    await expect(attempt()).rejects.toMatchObject({ code: "ACCOUNT_NOT_AVAILABLE" });
    expect((await AuthAttemptModel.findOne())?.reason).toBe("ACCOUNT_NOT_AVAILABLE");
    expect(await SessionModel.countDocuments()).toBe(0);
  });

  it("counts concurrent failures without losing telemetry", async () => {
    await seedUser();
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => attempt("wrong-password")));
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(await AuthAttemptModel.countDocuments({ outcome: "FAILURE" })).toBe(4);
    expect((await assessLoginAbuse({ email, ipHash })).accountFailures).toBe(4);
  });

  it("fails closed when assessment storage is unavailable", async () => {
    vi.spyOn(AuthAttemptModel, "countDocuments").mockRejectedValueOnce(new Error("test storage failure"));
    await expect(attempt()).rejects.toMatchObject({ code: "AUTH_UNAVAILABLE" });
    expect(await SessionModel.countDocuments()).toBe(0);
  });

  it("rolls back session creation when success telemetry cannot be stored", async () => {
    await seedUser();
    vi.spyOn(AuthAttemptModel, "create").mockRejectedValueOnce(new Error("test write failure"));
    await expect(attempt()).rejects.toMatchObject({ code: "AUTH_UNAVAILABLE" });
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_SUCCESS" })).toBe(0);
  });

  it("does not pool missing network identifiers into one IP bucket", async () => {
    await seedFailures(10, 5);
    const risk = await assessLoginAbuse({ email: "unrelated@example.com" });
    expect(risk.ipFailures).toBe(0);
    expect(risk.distinctAccountsFromIp).toBe(0);
    expect(risk.blocked).toBe(false);
  });
});

// These test admission itself: successful reservations deliberately remain in flight.
describe("Atomic admission", () => {
  it("admits exactly eight simultaneous requests for one account/source pair", async () => {
    const results = await Promise.allSettled(Array.from({ length: 12 }, () => admitLogin(email, ipHash)));
    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(8);
    expect(results.filter(result => result.status === "rejected")).toHaveLength(4);
    // Other networks remain available; there is no globally lockable account bucket.
    await expect(admitLogin(email, "independent-network")).resolves.toHaveProperty("ids");
    const first = results.find(result => result.status === "fulfilled");
    if (first?.status === "fulfilled") await releaseAdmission(first.value);
    await expect(admitLogin(email, ipHash)).resolves.toHaveProperty("ids");
  }, 60_000);
});
