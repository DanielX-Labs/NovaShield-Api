import { describe, expect, it, vi } from "vitest";

// Only the hashing boundary is mocked to verify initialization and execution order.
const mocks = vi.hoisted(() => ({
  hashPassword: vi.fn().mockResolvedValue("dummy-hash"),
  verifyPassword: vi.fn().mockResolvedValue(false),
}));
vi.mock("../../src/services/password/passwordHash.service.js", () => mocks);

describe("Dummy verification", () => {
  it("initializes once and never skips verification before explicit startup", async () => {
    const service = await import("../../src/services/password/dummyPassword.service.js");
    await Promise.all([
      service.performDummyPasswordVerification("candidate-one"),
      service.performDummyPasswordVerification("candidate-two"),
    ]);
    await service.initializeDummyPasswordHash();
    expect(mocks.hashPassword).toHaveBeenCalledTimes(1);
    expect(mocks.verifyPassword).toHaveBeenCalledWith("dummy-hash", "candidate-one");
    expect(mocks.verifyPassword).toHaveBeenCalledWith("dummy-hash", "candidate-two");
  });
});
