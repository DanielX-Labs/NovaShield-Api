import { createHmac } from "node:crypto";
import { env } from "../../config/env.js";

export function hashAuthIdentifier(value: string): string {
  // Separate email identifiers from IP hashes even while sharing the network key.
  return createHmac("sha256", env.IP_HASH_SECRET)
    .update("auth-email:")
    .update(value.normalize("NFKC").trim().toLowerCase())
    .digest("hex");
}
