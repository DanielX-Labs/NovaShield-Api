import argon2 from "argon2";
import { describe, expect, it, vi } from "vitest";

// Keep deterministic test configuration separate from developer secrets.
vi.mock("../../src/config/env.js", () => ({
  env: {
    PASSWORD_MAX_LENGTH: 128,
    AUTH_PEPPER: "test-only-pepper-never-use-in-production",
    ARGON2_MEMORY_COST: 19456,
    ARGON2_TIME_COST: 2,
    ARGON2_PARALLELISM: 1,
  },
}));
import {
  hashPassword,
  verifyPassword,
  needsPasswordRehash,
} from "../../src/services/password/passwordHash.service.js";

const password = "Orbit-Cedar!Lantern-47";

describe("Argon2id password hashing", () => {
  it("verifies correct passwords and rejects incorrect passwords", async () => {
    const hash = await hashPassword(password);
    expect(hash.startsWith("$argon2id$")).toBe(true);
    await expect(verifyPassword(hash, password)).resolves.toBe(true);
    await expect(verifyPassword(hash, "Wrong-Password-99"))
      .resolves.toBe(false);
    expect(needsPasswordRehash(hash)).toBe(false);
  });

  it("generates unique salts for identical passwords", async () => {
    const first = await hashPassword(password);
    const second = await hashPassword(password);
    expect(first).not.toBe(second);
    await expect(verifyPassword(first, password)).resolves.toBe(true);
    await expect(verifyPassword(second, password)).resolves.toBe(true);
  });

  it("requires the same pepper", async () => {
    const hash = await hashPassword(password);
    await expect(argon2.verify(hash, password)).resolves.toBe(false);
    await expect(argon2.verify(hash, password + "different-pepper"))
      .resolves.toBe(false);
    await expect(argon2.verify(
      hash,
      password + "test-only-pepper-never-use-in-production",
    )).resolves.toBe(true);
  });

  // Comparison normalization must never change the bytes being hashed.
  it("preserves whitespace and Unicode representations", async () => {
    const original = " Café-Cedar!Lantern-47 ";
    const hash = await hashPassword(original);
    await expect(verifyPassword(hash, original)).resolves.toBe(true);
    await expect(verifyPassword(hash, original.trim())).resolves.toBe(false);
    await expect(verifyPassword(hash, original.normalize("NFD")))
      .resolves.toBe(false);
  });

  it("fails closed on malformed hashes and excessive input", async () => {
    await expect(verifyPassword("invalid", password)).resolves.toBe(false);
    await expect(hashPassword("a".repeat(129))).rejects.toThrow(RangeError);
    await expect(verifyPassword("invalid", "a".repeat(129)))
      .resolves.toBe(false);
    expect(needsPasswordRehash("invalid")).toBe(true);
  });

  it("detects outdated cost settings", async () => {
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 8192,
      timeCost: 1,
      parallelism: 1,
    });
    expect(needsPasswordRehash(hash)).toBe(true);
  });
});
