import { createHmac } from "node:crypto";
import { env } from "../../config/env.js";

// Separate the network-correlation key from password and OTP protection.
export function hashIpAddress(ip?: string): string | undefined {
  if (!ip) return undefined;

  return createHmac("sha256", env.IP_HASH_SECRET)
    .update(ip)
    .digest("hex");
}
