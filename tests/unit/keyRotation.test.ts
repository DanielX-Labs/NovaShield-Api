import argon2 from "argon2";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../../src/config/env.js", async () => ({
  env: { ...(await import("../helpers/testEnv.js")).testEnv },
}));
import { env } from "../../src/config/env.js";
import { hashPassword, verifyPassword, needsPasswordRehash } from "../../src/services/password/passwordHash.service.js";
import { createAccessToken, verifyAccessToken } from "../../src/services/session/accessToken.service.js";
import { encryptOutbox, decryptOutbox } from "../../src/services/email/outboxCrypto.service.js";

beforeEach(() => Object.assign(env, {
  PASSWORD_PEPPER_ID: "legacy", PASSWORD_PEPPER_KEYS: {}, AUTH_HASH_CONCURRENCY: 4,
  JWT_ACCESS_KEY_ID: "v1", JWT_PREVIOUS_KEYS: {}, JWT_ACCESS_SECRET: "old-jwt-secret-with-enough-entropy-for-tests",
  OUTBOX_KEY_ID: "v1", OUTBOX_ENCRYPTION_KEY: "ab".repeat(32), OUTBOX_PREVIOUS_KEYS: {},
}));
const password = "Orbit-Cedar!Lantern-47";

describe("Secret rotation and resource limits", () => {
  it("verifies legacy and previous-version credentials during pepper rotation", async () => {
    const legacy = await argon2.hash(password + env.AUTH_PEPPER, { type: argon2.argon2id });
    const old = await hashPassword(password);
    Object.assign(env, { PASSWORD_PEPPER_ID: "v2", PASSWORD_PEPPER_KEYS: { v2: "a-new-independent-password-pepper-key" } });
    expect(await verifyPassword(legacy, password)).toBe(true);
    expect(await verifyPassword(old, password)).toBe(true);
    expect(needsPasswordRehash(old)).toBe(true);
    const current = await hashPassword(password);
    expect(current.startsWith("ns1:v2:")).toBe(true);
    expect(needsPasswordRehash(current)).toBe(false);
    await expect(verifyPassword(current.replace("ns1:v2:", "ns1:unknown:"), password))
      .rejects.toMatchObject({ code: "AUTH_UNAVAILABLE" });
  }, 30_000);
  it("accepts retained JWT keys and rejects them after retirement", () => {
    const claims = { sub: "user", sid: "session", type: "access" as const, ver: 1 };
    const old = createAccessToken(claims);
    Object.assign(env, { JWT_ACCESS_KEY_ID: "v2", JWT_PREVIOUS_KEYS: { v1: env.JWT_ACCESS_SECRET },
      JWT_ACCESS_SECRET: "new-jwt-secret-with-enough-entropy-for-tests" });
    expect(verifyAccessToken(old)).toEqual(claims);
    expect(verifyAccessToken(createAccessToken(claims))).toEqual(claims);
    Object.assign(env, { JWT_PREVIOUS_KEYS: {} });
    expect(() => verifyAccessToken(old)).toThrow();
  });
  it("authenticates encrypted payloads and supports retained outbox keys", () => {
    const encoded = encryptOutbox("private-otp-value", "job-one");
    expect(encoded).not.toContain("private-otp-value");
    expect(() => decryptOutbox(encoded, "job-two")).toThrow();
    expect(() => decryptOutbox(encoded.slice(0, -3) + "xxx", "job-one")).toThrow();
    Object.assign(env, { OUTBOX_KEY_ID: "v2", OUTBOX_PREVIOUS_KEYS: { v1: env.OUTBOX_ENCRYPTION_KEY },
      OUTBOX_ENCRYPTION_KEY: "cd".repeat(32) });
    expect(decryptOutbox(encoded, "job-one")).toBe("private-otp-value");
  });
  it("rejects excess Argon2 work without growing an unbounded queue", async () => {
    Object.assign(env, { AUTH_HASH_CONCURRENCY: 1 });
    const first = hashPassword(password);
    await expect(hashPassword(password)).rejects.toMatchObject({ code: "AUTH_UNAVAILABLE" });
    await first;
    await expect(hashPassword(password)).resolves.toContain("$argon2id$");
  });
});
