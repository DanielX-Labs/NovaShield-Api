import type { Request, Response, NextFunction } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Isolate live-state validation from JWT cryptography, tested in token.test.ts.
const mocks = vi.hoisted(() => ({
  token: vi.fn(),
  user: vi.fn(),
  session: vi.fn(),
  credential: vi.fn(),
}));
vi.mock("../../src/services/session/accessToken.service.js", () => ({
  verifyAccessToken: mocks.token,
}));
vi.mock("../../src/models/AuthUser.model.js", () => ({
  AuthUserModel: { findById: mocks.user },
}));
vi.mock("../../src/models/Session.model.js", () => ({
  SessionModel: { findOne: mocks.session },
}));
vi.mock("../../src/models/Credential.model.js", () => ({
  CredentialModel: { findOne: mocks.credential },
}));
import { authenticate } from "../../src/middleware/authenticate.middleware.js";

const subject = "0123456789abcdef01234567";
beforeEach(() => {
  vi.resetAllMocks();
  mocks.token.mockReturnValue({ sub: subject, sid: "session", type: "access", ver: 1 });
  mocks.user.mockResolvedValue({ status: "ACTIVE", isEmailVerified: true });
  mocks.session.mockResolvedValue({
    sessionId: "session", passwordVersion: 1,
    expiresAt: new Date(Date.now() + 60_000),
  });
  mocks.credential.mockResolvedValue({ passwordVersion: 1 });
});

async function run() {
  const req = { get: () => "Bearer token" } as unknown as Request;
  const next = vi.fn();
  await authenticate(req, {} as Response, next as NextFunction);
  return { req, next };
}

describe("Live authentication state", () => {
  it("attaches only the validated user and session context", async () => {
    const { req, next } = await run();
    expect(next).toHaveBeenCalledWith();
    expect(req.auth).toEqual({
      userId: subject, sessionId: "session", passwordVersion: 1,
    });
    expect(mocks.session).toHaveBeenCalledWith({
      userId: expect.anything(), sessionId: "session",
    });
  });

  it.each(["expired", "revoked", "missing", "legacy"])(
    "rejects a %s session even when JWT verification succeeds",
    async (state) => {
      mocks.session.mockResolvedValue(state === "missing" ? null : {
        sessionId: "session",
        passwordVersion: state === "legacy" ? undefined : 1,
        expiresAt: new Date(Date.now() + (state === "expired" ? -1 : 60_000)),
        ...(state === "revoked" ? { revokedAt: new Date() } : {}),
      });
      const { req, next } = await run();
      expect(next).toHaveBeenCalledWith(expect.objectContaining({
        statusCode: 401, code: "INVALID_ACCESS_TOKEN",
      }));
      expect(req.auth).toBeUndefined();
    },
  );

  it("rejects missing credentials without attaching authentication context", async () => {
    mocks.credential.mockResolvedValue(null);
    const { req, next } = await run();
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401 }));
    expect(req.auth).toBeUndefined();
  });
});
