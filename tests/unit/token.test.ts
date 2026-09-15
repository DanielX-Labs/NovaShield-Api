import jwt from "jsonwebtoken";
import { describe, expect, it, vi } from "vitest";

// Fixed test secrets do not load the private environment.
vi.mock("../../src/config/env.js", () => ({
  env: {
    JWT_ACCESS_SECRET: "unit-test-access-secret-not-for-production",
    ACCESS_TOKEN_TTL_MINUTES: 15,
    IP_HASH_SECRET: "unit-test-network-secret-not-for-production",
  },
}));
import {
  createAccessToken, verifyAccessToken,
} from "../../src/services/session/accessToken.service.js";
import {
  generateRefreshToken, hashRefreshToken, parseRefreshToken,
} from "../../src/services/session/refreshTokenCrypto.service.js";
import { hashIpAddress } from "../../src/services/security/networkIdentity.service.js";

const payload = {
  sub: "user-123", sid: "session-123", type: "access" as const, ver: 1,
};
const secret = "unit-test-access-secret-not-for-production";

describe("Access tokens", () => {
  it("issues pinned claims and a 15-minute expiry", () => {
    const token = createAccessToken(payload);
    expect(verifyAccessToken(token)).toEqual(payload);
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    expect(decoded.exp! - decoded.iat!).toBe(900);
    expect(decoded.iss).toBe("novashield");
    expect(decoded.aud).toBe("expensehub-api");
  });

  it.each([
    { issuer: "other" },
    { audience: "other" },
    { algorithm: "HS384" as const },
    { expiresIn: -1 },
  ])("rejects unexpected signing constraints %j", (overrides) => {
    const token = jwt.sign(payload, secret, {
      algorithm: "HS256",
      issuer: "novashield",
      audience: "expensehub-api",
      expiresIn: 900,
      ...overrides,
    });
    expect(() => verifyAccessToken(token)).toThrow();
  });

  it.each([
    { type: "refresh" },
    { ver: 0 },
    { ver: 1.5 },
    { sub: "" },
    { sid: "" },
    { iat: Math.floor(Date.now() / 1000) + 1000 },
  ])("rejects malformed application claims %j", (overrides) => {
    const token = jwt.sign({ ...payload, ...overrides }, secret, {
      issuer: "novashield", audience: "expensehub-api", expiresIn: 900,
    });
    expect(() => verifyAccessToken(token)).toThrow();
  });

  it("rejects tokens lacking expiration or signed with another key", () => {
    const noExpiry = jwt.sign(payload, secret, {
      issuer: "novashield", audience: "expensehub-api",
    });
    const wrongKey = jwt.sign(payload, "different-secret", {
      issuer: "novashield", audience: "expensehub-api", expiresIn: 900,
    });
    expect(() => verifyAccessToken(noExpiry)).toThrow();
    expect(() => verifyAccessToken(wrongKey)).toThrow();
    expect(() => verifyAccessToken("x".repeat(4097))).toThrow();
  });
});

describe("Opaque refresh tokens", () => {
  it("generates independent random secrets and stores only a digest", () => {
    const first = generateRefreshToken();
    const second = generateRefreshToken();
    expect(first.rawToken).not.toBe(second.rawToken);
    expect(first.secret).not.toBe(second.secret);
    expect(parseRefreshToken(first.rawToken)).toEqual({
      tokenId: first.tokenId, secret: first.secret,
    });
    expect(hashRefreshToken(first.rawToken)).toMatch(/^[a-f0-9]{64}$/u);
    expect(hashRefreshToken(first.rawToken)).not.toBe(first.rawToken);
    expect(hashRefreshToken(first.rawToken)).not.toBe(hashRefreshToken(second.rawToken));
  });

  it("rejects malformed, overlong, and ambiguous encodings", () => {
    const valid = generateRefreshToken().rawToken;
    for (const token of [
      "", "invalid", valid + ".", valid + "x", valid.slice(1),
      valid.replace(".", ".."), "z".repeat(24) + valid.slice(24),
      valid.slice(0, 25) + "/".repeat(64),
    ]) expect(parseRefreshToken(token)).toBeNull();
  });
});

describe("Network identifiers", () => {
  it("correlates the same IP without exposing it", () => {
    const hash = hashIpAddress("127.0.0.1");
    expect(hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(hash).toBe(hashIpAddress("127.0.0.1"));
    expect(hash).not.toBe(hashIpAddress("127.0.0.2"));
    expect(hashIpAddress()).toBeUndefined();
  });
});
