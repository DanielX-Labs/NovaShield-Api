import type { Response } from "express";
import { describe, expect, it, vi } from "vitest";

// Exercise both local HTTP and production HTTPS settings without actual secrets.
vi.mock("../../src/config/env.js", () => ({
  env: {
    REFRESH_COOKIE_NAME: "novashield_refresh",
    COOKIE_SECURE: false,
    COOKIE_SAME_SITE: "lax",
    REFRESH_TOKEN_TTL_DAYS: 7,
  },
}));
import { env } from "../../src/config/env.js";
import {
  setRefreshCookie, clearRefreshCookie,
} from "../../src/services/session/refreshCookie.service.js";

describe("Refresh cookies", () => {
  it("uses matching HttpOnly cookie scope for set and clear", () => {
    const cookie = vi.fn();
    const clearCookie = vi.fn();
    const res = { cookie, clearCookie } as unknown as Response;
    setRefreshCookie(res, "opaque-test-value");
    clearRefreshCookie(res);
    const scope = {
      httpOnly: true, secure: false, sameSite: "lax", path: "/api/v1/auth",
    };
    expect(cookie).toHaveBeenCalledWith(
      "novashield_refresh", "opaque-test-value",
      { ...scope, maxAge: 7 * 24 * 60 * 60 * 1000 },
    );
    expect(clearCookie).toHaveBeenCalledWith("novashield_refresh", scope);
  });

  it("honors secure cross-site configuration", () => {
    Object.assign(env, { COOKIE_SECURE: true, COOKIE_SAME_SITE: "none" });
    const cookie = vi.fn();
    setRefreshCookie({ cookie } as unknown as Response, "test");
    expect(cookie).toHaveBeenCalledWith(
      "novashield_refresh", "test",
      expect.objectContaining({ secure: true, sameSite: "none" }),
    );
  });
});
