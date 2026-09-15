import { Types } from "mongoose";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Isolate orchestration to verify invalid input never reaches costly work.
const mocks = vi.hoisted(() => ({
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
  needsPasswordRehash: vi.fn(),
  isPasswordReused: vi.fn(),
  checkBreachedPassword: vi.fn(),
}));
vi.mock("../../src/config/env.js", () => ({
  env: {
    PASSWORD_MIN_LENGTH: 15,
    PASSWORD_MAX_LENGTH: 128,
    BREACHED_PASSWORD_FAIL_MODE: "closed",
  },
}));
vi.mock("../../src/services/password/breachedPassword.service.js", () => mocks);
import { env } from "../../src/config/env.js";
import { BreachedPasswordServiceError } from "../../src/services/password/breachedPassword.types.js";
vi.mock("../../src/services/password/passwordHash.service.js", () => mocks);
vi.mock("../../src/services/password/passwordHistory.service.js", () => mocks);
import {
  createPasswordHash,
  validatePasswordChange,
} from "../../src/services/password/password.service.js";

beforeEach(() => {
  vi.resetAllMocks();
  Object.assign(env, { BREACHED_PASSWORD_FAIL_MODE: "closed" });
  mocks.checkBreachedPassword.mockResolvedValue({
    checked: true, breached: false, occurrenceCount: 0,
  });
});

describe("Password workflow", () => {
  // Screening must finish before hashing or reading password history.
  it("blocks compromised passwords in both workflows", async () => {
    mocks.checkBreachedPassword.mockResolvedValue({
      checked: true, breached: true, occurrenceCount: 42,
    });
    await expect(createPasswordHash("Orbit-Cedar!Lantern-47"))
      .rejects.toMatchObject({ code: "PASSWORD_COMPROMISED" });
    await expect(validatePasswordChange(
      new Types.ObjectId(), "Orbit-Cedar!Lantern-47",
    )).rejects.toMatchObject({ code: "PASSWORD_COMPROMISED" });
    expect(mocks.hashPassword).not.toHaveBeenCalled();
    expect(mocks.isPasswordReused).not.toHaveBeenCalled();
  });

  it("fails closed during outages and respects explicit fail-open mode", async () => {
    mocks.checkBreachedPassword.mockRejectedValue(
      new BreachedPasswordServiceError("Unavailable"),
    );
    await expect(createPasswordHash("Orbit-Cedar!Lantern-47"))
      .rejects.toMatchObject({
        code: "PASSWORD_SECURITY_CHECK_UNAVAILABLE", statusCode: 503,
      });
    Object.assign(env, { BREACHED_PASSWORD_FAIL_MODE: "open" });
    mocks.hashPassword.mockResolvedValue("encoded");
    await expect(createPasswordHash("Orbit-Cedar!Lantern-47"))
      .resolves.toBe("encoded");
  });
  it("rejects policy failures before hashing or reading history", async () => {
    await expect(createPasswordHash("short")).rejects.toMatchObject({
      code: "PASSWORD_POLICY_VIOLATION", statusCode: 400,
    });
    await expect(validatePasswordChange(new Types.ObjectId(), "short"))
      .rejects.toMatchObject({ code: "PASSWORD_POLICY_VIOLATION" });
    expect(mocks.hashPassword).not.toHaveBeenCalled();
    expect(mocks.isPasswordReused).not.toHaveBeenCalled();
  });

  it("hashes an accepted password unchanged", async () => {
    const password = "Orbit-Cedar!Lantern-47";
    mocks.hashPassword.mockResolvedValue("encoded");
    await expect(createPasswordHash(password)).resolves.toBe("encoded");
    expect(mocks.hashPassword).toHaveBeenCalledWith(password);
  });

  it("rejects reuse and permits a fresh password", async () => {
    const userId = new Types.ObjectId();
    mocks.isPasswordReused.mockResolvedValueOnce(true);
    await expect(validatePasswordChange(userId, "Orbit-Cedar!Lantern-47"))
      .rejects.toMatchObject({ code: "PASSWORD_RECENTLY_USED" });
    mocks.isPasswordReused.mockResolvedValueOnce(false);
    await expect(validatePasswordChange(userId, "Orbit-Cedar!Lantern-47"))
      .resolves.toBeUndefined();
  });
});
