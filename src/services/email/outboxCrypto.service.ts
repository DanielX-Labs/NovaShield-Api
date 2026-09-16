import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { env } from "../../config/env.js";

export function encryptOutbox(value: string, binding: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(env.OUTBOX_ENCRYPTION_KEY, "hex"), nonce);
  cipher.setAAD(Buffer.from(binding));
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [env.OUTBOX_KEY_ID ?? "v1", nonce.toString("base64url"),
    cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
}

export function decryptOutbox(value: string, binding: string): string {
  const [id, nonce, tag, ciphertext, extra] = value.split(".");
  if (!id || !nonce || !tag || !ciphertext || extra) throw new Error("Invalid outbox envelope.");
  const key = id === (env.OUTBOX_KEY_ID ?? "v1")
    ? env.OUTBOX_ENCRYPTION_KEY : env.OUTBOX_PREVIOUS_KEYS?.[id];
  if (!key) throw new Error("Outbox encryption key unavailable.");
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key, "hex"), Buffer.from(nonce, "base64url"));
  decipher.setAAD(Buffer.from(binding));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]).toString("utf8");
}
