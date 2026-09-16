import argon2 from "argon2";
import { env } from "../../config/env.js";
import { AppError } from "../../utils/AppError.js";

let active = 0;
async function bounded<T>(work: () => Promise<T>): Promise<T> {
  // No unbounded queue: excess work receives a retryable 503 before allocating Argon2 memory.
  if (active >= (env.AUTH_HASH_CONCURRENCY ?? 4)) {
    throw new AppError("Password verification is busy. Please try again.", 503, "AUTH_UNAVAILABLE");
  }
  active += 1;
  try { return await work(); } finally { active -= 1; }
}
function currentId(): string { return env.PASSWORD_PEPPER_ID ?? "legacy"; }
function key(id: string): string {
  const value = id === "legacy" ? env.AUTH_PEPPER : env.PASSWORD_PEPPER_KEYS?.[id];
  if (!value) throw new AppError("Password verification is temporarily unavailable.", 503, "AUTH_UNAVAILABLE");
  return value;
}
function parse(value: string): { id: string; hash: string } {
  // Unversioned records retain their original AUTH_PEPPER during migration.
  if (value.startsWith("$argon2")) return { id: "legacy", hash: value };
  const match = /^ns1:([a-zA-Z0-9_-]{1,32}):(\$argon2.+)$/u.exec(value);
  if (!match) throw new Error("Invalid credential envelope.");
  return { id: match[1]!, hash: match[2]! };
}
const options = () => ({
  memoryCost: env.ARGON2_MEMORY_COST,
  timeCost: env.ARGON2_TIME_COST,
  parallelism: env.ARGON2_PARALLELISM,
});

export async function hashPassword(password: string): Promise<string> {
  if (!password || password.length > env.PASSWORD_MAX_LENGTH) throw new RangeError("Password length is outside hashing limits.");
  const id = currentId();
  const hash = await bounded(() => argon2.hash(password + key(id), {
    type: argon2.argon2id, ...options(),
  }));
  // This application envelope records the key ID; the enclosed hash remains standard Argon2id.
  return `ns1:${id}:${hash}`;
}
export async function verifyPassword(passwordHash: string, candidate: string): Promise<boolean> {
  if (!candidate || candidate.length > env.PASSWORD_MAX_LENGTH) return false;
  try {
    const stored = parse(passwordHash);
    return await bounded(() => argon2.verify(stored.hash, candidate + key(stored.id)));
  } catch (error) {
    if (error instanceof AppError) throw error;
    return false;
  }
}
export function needsPasswordRehash(passwordHash: string): boolean {
  try {
    const stored = parse(passwordHash);
    return !passwordHash.startsWith("ns1:") || stored.id !== currentId()
      || !stored.hash.startsWith("$argon2id$") || argon2.needsRehash(stored.hash, options());
  } catch { return true; }
}
