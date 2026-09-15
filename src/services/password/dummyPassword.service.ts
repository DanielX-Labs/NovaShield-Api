import { randomBytes } from "node:crypto";
import { hashPassword, verifyPassword } from "./passwordHash.service.js";

let initialization: Promise<string> | undefined;

// Cache one Argon2 hash per process, sharing initialization across concurrent calls.
export async function initializeDummyPasswordHash(): Promise<void> {
  initialization ??= hashPassword(randomBytes(32).toString("hex"));
  await initialization;
}

export async function performDummyPasswordVerification(password: string): Promise<void> {
  // Never silently skip work when used outside normal server startup (e.g. tests).
  await initializeDummyPasswordHash();
  const hash = await initialization!;
  await verifyPassword(hash, password);
}
