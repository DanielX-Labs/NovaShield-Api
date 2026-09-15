import { createHash, randomBytes } from "node:crypto";
import { Types } from "mongoose";
import type { RefreshTokenParts } from "./token.types.js";

// 48 random bytes provide 384 bits of entropy; ObjectId is only a lookup key.
export function generateRefreshToken(): RefreshTokenParts {
  const tokenId = new Types.ObjectId().toHexString();
  const secret = randomBytes(48).toString("base64url");
  return { tokenId, secret, rawToken: `${tokenId}.${secret}` };
}

// Fast SHA-256 is suitable for high-entropy tokens, not human passwords.
export function hashRefreshToken(rawToken: string): string {
  return createHash("sha256").update(rawToken, "utf8").digest("hex");
}

export function parseRefreshToken(
  rawToken: string,
): Pick<RefreshTokenParts, "tokenId" | "secret"> | null {
  // Accept exactly our issued format, with no extra separators or trailing bytes.
  if (rawToken.length !== 89
    || !/^[a-f0-9]{24}\.[A-Za-z0-9_-]{64}$/u.test(rawToken)) {
    return null;
  }
  return { tokenId: rawToken.slice(0, 24), secret: rawToken.slice(25) };
}
