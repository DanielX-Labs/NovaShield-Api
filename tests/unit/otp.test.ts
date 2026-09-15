import { describe, expect, it, vi } from "vitest";

// No production pepper or private environment is loaded by these tests.
vi.mock("../../src/config/env.js", () => ({
  env: { AUTH_PEPPER: "otp-test-pepper-only" },
}));
import { generateOtp, hashOtp, verifyOtpHash } from "../../src/services/otp/otp.service.js";

describe("OTP cryptography", () => {
  it("generates six-digit codes", () => {
    for (let i = 0; i < 100; i += 1) {
      expect(generateOtp()).toMatch(/^[1-9]\d{5}$/u);
    }
  });

  it("stores a digest and verifies only the correct code and challenge", () => {
    const hash = hashOtp("123456", "challenge-one");
    expect(hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(hash).not.toBe("123456");
    expect(verifyOtpHash("123456", "challenge-one", hash)).toBe(true);
    expect(verifyOtpHash("654321", "challenge-one", hash)).toBe(false);
    expect(verifyOtpHash("123456", "challenge-two", hash)).toBe(false);
  });

  // Malformed hex must not be silently truncated into a valid digest.
  it("rejects malformed hashes and OTP values", () => {
    const hash = hashOtp("123456", "challenge");
    for (const invalid of ["", "zz", hash + "zz", hash.slice(2)]) {
      expect(verifyOtpHash("123456", "challenge", invalid)).toBe(false);
    }
    expect(verifyOtpHash("1234567", "challenge", hash)).toBe(false);
  });
});
