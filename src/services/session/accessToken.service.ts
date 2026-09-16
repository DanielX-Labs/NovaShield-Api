import jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import type { AccessTokenPayload } from "./token.types.js";

const issuer = "novashield";
const audience = env.JWT_ACCESS_AUDIENCE ?? "expensehub-api";

// Pin the algorithm, issuer, audience, and lifetime at issuance.
export function createAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    algorithm: "HS256",
    keyid: env.JWT_ACCESS_KEY_ID ?? "v1",
    expiresIn: env.ACCESS_TOKEN_TTL_MINUTES * 60,
    issuer,
    audience,
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  // Limit parsing work before invoking the JWT library.
  if (token.length > 4096) throw new Error("Invalid access token.");
  // kid selects only a configured key; it is never a path, URL, or dynamically loaded secret.
  const header = jwt.decode(token, { complete: true })?.header;
  const kid = header?.kid;
  if (kid !== undefined && !/^[a-zA-Z0-9_-]{1,32}$/u.test(kid)) throw new Error("Invalid key ID.");
  const secret = kid === (env.JWT_ACCESS_KEY_ID ?? "v1") ? env.JWT_ACCESS_SECRET
    : !kid ? (env.JWT_PREVIOUS_KEYS?.legacy ?? env.JWT_ACCESS_SECRET)
    : env.JWT_PREVIOUS_KEYS?.[kid];
  if (!secret) throw new Error("Unknown signing key.");
  const decoded = jwt.verify(token, secret, {
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

  // Return only allowlisted claims; authenticated middleware also checks session state.
  return {
    sub: decoded.sub,
    sid: decoded.sid,
    type: "access",
    ver: decoded.ver,
  };
}
