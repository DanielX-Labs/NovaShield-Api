import argon2 from "argon2";
import { env } from "../../config/env.js";

// Preserve whitespace and Unicode exactly; the pepper stays outside MongoDB.
function applyPepper(password: string): string {
  return `${password}${env.AUTH_PEPPER}`;
}

export async function hashPassword(password: string): Promise<string> {
  // Enforce the resource limit even when called without the policy service.
  if (!password || password.length > env.PASSWORD_MAX_LENGTH) {
    throw new RangeError("Password length is outside hashing limits.");
  }

  // Argon2 generates a fresh random salt and embeds parameters in the hash.
  return argon2.hash(applyPepper(password), {
    type: argon2.argon2id,
    memoryCost: env.ARGON2_MEMORY_COST,
    timeCost: env.ARGON2_TIME_COST,
    parallelism: env.ARGON2_PARALLELISM,
  });
}

export async function verifyPassword(
  passwordHash: string,
  candidatePassword: string,
): Promise<boolean> {
  // Verification does not apply new-password policy to existing passwords.
  if (!candidatePassword
    || candidatePassword.length > env.PASSWORD_MAX_LENGTH) {
    return false;
  }

  try {
    return await argon2.verify(
      passwordHash,
      applyPepper(candidatePassword),
    );
  } catch {
    // Corrupt hashes must fail closed without exposing internal errors.
    return false;
  }
}

export function needsPasswordRehash(passwordHash: string): boolean {
  // Malformed hashes and older algorithms need replacement after verification.
  try {
    return !passwordHash.startsWith("$argon2id$")
      || argon2.needsRehash(passwordHash, {
        memoryCost: env.ARGON2_MEMORY_COST,
        timeCost: env.ARGON2_TIME_COST,
        parallelism: env.ARGON2_PARALLELISM,
      });
  } catch {
    return true;
  }
}
