import { describe, expect, it, vi } from "vitest";

// Unit tests use fixed settings and never load the private .env file.
vi.mock("../../src/config/env.js", () => ({
  env: { PASSWORD_MIN_LENGTH: 15, PASSWORD_MAX_LENGTH: 128 },
}));
import { assessPassword } from "../../src/services/password/passwordPolicy.service.js";

describe("Password policy", () => {
  it.each([
    ["", "PASSWORD_REQUIRED"],
    ["Abc123!", "PASSWORD_TOO_SHORT"],
    ["password123", "PASSWORD_COMMON"],
    ["Orbit-aaaa-Lantern", "PASSWORD_REPEATED_PATTERN"],
    ["Orbit-abcd-Lantern", "PASSWORD_SEQUENTIAL_PATTERN"],
    ["Orbit-4321-Lantern", "PASSWORD_SEQUENTIAL_PATTERN"],
    ["Orbit-qwer-Lantern", "PASSWORD_SEQUENTIAL_PATTERN"],
  ])("rejects predictable input (%s)", (password, code) => {
    expect(assessPassword(password).issues.map((issue) => issue.code))
      .toContain(code);
  });

  // Large input should stop before running the remaining policy checks.
  it("rejects oversized input immediately", () => {
    expect(assessPassword("a".repeat(1_000_000)).issues)
      .toEqual([expect.objectContaining({ code: "PASSWORD_TOO_LONG" })]);
  });

  it("detects email and name context with comparison normalization", () => {
    const result = assessPassword("ＣＨＩＮＥＭＥＲＥＭ-Cedar-Lantern", {
      email: "chinemerem@example.com",
      name: "Chinemerem Customer",
    });
    expect(result.issues.map((issue) => issue.code)).toEqual(
      expect.arrayContaining([
        "PASSWORD_CONTAINS_EMAIL",
        "PASSWORD_CONTAINS_NAME",
      ]),
    );
  });

  it.each([
    "Orbit-Cedar!Lantern-47",
    "velvet cedar lantern",
    "Oak!Birch-47",
    "Oak!Birch-47x",
  ])("checks passphrases without composition rules (%s)", (password) => {
    expect(assessPassword(password).valid).toBe(password.length >= 15);
  });

  it("accepts the maximum permitted length", () => {
    expect(assessPassword("Z!m7".repeat(32)).valid).toBe(true);
  });
});
