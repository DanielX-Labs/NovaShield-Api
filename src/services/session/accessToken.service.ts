import jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import type { AccessTokenPayload } from "./token.types.js";

const issuer = "novashield";
const audience = "expensehub-api";

// Pin the algorithm, issuer, audience, and lifetime at issuance.
export function createAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    algorithm: "HS256",
    expiresIn: env.ACCESS_TOKEN_TTL_MINUTES * 60,
    issuer,
    audience,
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  // Limit parsing work before invoking the JWT library.
  if (token.length > 4096) throw new Error("Invalid access token.");
  const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET, {
    algorithms: ["HS256"],
    issuer,
    audience,
    maxAge: env.ACCESS_TOKEN_TTL_MINUTES * 60,
  });

  // A valid signature alone is insufficient: enforce the application claim shape.
  if (typeof decoded === "string"
    || decoded.type !== "access"
    || typeof decoded.sub !== "string" || decoded.sub.length === 0
    || typeof decoded.sid !== "string" || decoded.sid.length === 0
    || !Number.isSafeInteger(decoded.ver) || decoded.ver < 1
    || typeof decoded.exp !== "number" || !Number.isSafeInteger(decoded.exp)
    || typeof decoded.iat !== "number" || !Number.isSafeInteger(decoded.iat)
    || decoded.iat > Math.floor(Date.now() / 1000)
    || decoded.exp <= decoded.iat
    || decoded.exp - decoded.iat > env.ACCESS_TOKEN_TTL_MINUTES * 60) {
    throw new Error("Invalid access token payload.");
  }

  // Return only allowlisted claims; future middleware must also check session state.
  return {
    sub: decoded.sub,
    sid: decoded.sid,
    type: "access",
    ver: decoded.ver,
  };
}
