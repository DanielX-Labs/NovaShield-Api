// Reuse isolated database lifecycle and synthetic configuration, not production data.
import "../helpers/authIntegration.js";
import { EventEmitter } from "node:events";
import type { Request, Response } from "express";
import { describe, it, expect, vi } from "vitest";
import { authAbuseLimit } from "../../src/middleware/authAbuse.middleware.js";
import { AbuseBucketModel } from "../../src/models/AbuseBucket.model.js";

describe("Shared IPv6 admission", () => {
  it("bounds rotating hosts while admitting neighbors and refunding successful work", async () => {
    // A small test budget exercises the same middleware used with the larger shared quota.
    const limit = authAbuseLimit("test-network", 4, false, 900_000, true, true);
    async function attempt(ip: string, success = false): Promise<unknown> {
      const response = Object.assign(new EventEmitter(), { statusCode: 200, setHeader: vi.fn() });
      const error = await new Promise<unknown>(resolve => {
        void limit({ ip, id: "test" } as Request, response as unknown as Response,
          error => resolve(error));
      });
      if (!error && success) response.emit("finish");
      return error;
    }
    for (let i = 1; i <= 4; i += 1) {
      expect(await attempt(`2001:db8:1:2::${i}`)).toBeUndefined();
    }
    expect(await attempt("2001:db8:1:2::99")).toMatchObject({ statusCode: 429 });
    expect(await attempt("2001:db8:1:3::1", true)).toBeUndefined();
    await vi.waitFor(async () => {
      expect(await AbuseBucketModel.countDocuments({ count: 0 })).toBe(1);
    }, { timeout: 10_000 });
    // IPv4 has its own host protection, not this IPv6 network quota.
    expect(await attempt("192.0.2.1")).toBeUndefined();
    expect(await AbuseBucketModel.countDocuments()).toBe(2);
  });
});
