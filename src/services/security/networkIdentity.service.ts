import { createHmac } from "node:crypto";
import { isIP } from "node:net";
import { env } from "../../config/env.js";

// Expand IPv6 consistently, including IPv4-mapped addresses supplied by proxies.
export function canonicalAddress(ip: string): string {
  if (isIP(ip) === 4) return ip;
  if (isIP(ip) !== 6) throw new Error("Invalid network address.");
  const host = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  const [left, right] = host.split("::");
  const start = left ? left.split(":") : [];
  const end = right ? right.split(":") : [];
  const words = right !== undefined
    ? [...start, ...Array<string>(8 - start.length - end.length).fill("0"), ...end]
    : start;
  const values = words.map(word => Number.parseInt(word, 16));
  if (values.slice(0, 5).every(value => value === 0) && values[5] === 65535) {
    return [values[6]! >> 8, values[6]! & 255, values[7]! >> 8, values[7]! & 255].join(".");
  }
  return values.map(value => value.toString(16).padStart(4, "0")).join(":");
}

// Keep exact-address signals separate from the more permissive shared /64 budget.
export function hashNetworkAddress(ip?: string): string | undefined {
  if (!ip) return undefined;
  const address = canonicalAddress(ip);
  if (!address.includes(":")) return undefined;
  return createHmac("sha256", env.IP_HASH_SECRET)
    .update(`network-v6:${address.split(":").slice(0, 4).join(":")}/64`)
    .digest("hex");
}

// Separate the network-correlation key from password and OTP protection.
export function hashIpAddress(ip?: string): string | undefined {
  if (!ip) return undefined;

  return createHmac("sha256", env.IP_HASH_SECRET)
    .update(canonicalAddress(ip))
    .digest("hex");
}
