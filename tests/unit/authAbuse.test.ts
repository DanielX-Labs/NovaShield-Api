import { describe, expect, it, vi } from "vitest";

// Unit tests use fixed settings and cannot open a database connection.
vi.mock("../../src/config/env.js", () => ({ env: {
  AUTH_PROGRESSIVE_DELAY_AFTER: 3,
  AUTH_PROGRESSIVE_DELAY_BASE_MS: 500,
  AUTH_PROGRESSIVE_DELAY_MAX_MS: 5000,
  IP_HASH_SECRET: "unit-test-network-key-not-for-production",
} }));
import { calculateProgressiveDelay } from "../../src/services/security/authAbuse.service.js";
import { hashAuthIdentifier } from "../../src/services/security/identifierHash.service.js";
import { hashIpAddress } from "../../src/services/security/networkIdentity.service.js";
import { delay } from "../../src/utils/delay.js";

describe("Authentication abuse primitives", () => {
  it.each([[0, 0], [2, 0], [3, 500], [4, 1000], [5, 2000], [6, 4000], [7, 5000], [10000, 5000]])(
    "bounds the delay after %i failures to %i ms", (failures, expected) => {
      expect(calculateProgressiveDelay(failures)).toBe(expected);
    },
  );
  it("normalizes protected account identifiers and separates them from IP hashes", () => {
    const hash = hashAuthIdentifier(" Customer@Example.com ");
    expect(hash).toBe(hashAuthIdentifier("customer@example.com"));
    expect(hash).toBe(hashAuthIdentifier("\uff43ustomer@example.com"));
    expect(hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(hash).not.toBe(hashIpAddress("customer@example.com"));
  });
  it("uses a nonblocking timer for the requested delay", async () => {
    vi.useFakeTimers();
    try {
      let complete = false;
      const pending = delay(500).then(() => { complete = true; });
      await vi.advanceTimersByTimeAsync(499);
      expect(complete).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await pending;
      expect(complete).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
