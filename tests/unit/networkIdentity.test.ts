import { describe, it, expect, vi } from "vitest";
vi.mock("../../src/config/env.js", () => ({ env: { IP_HASH_SECRET: "test-network-key" } }));
import { canonicalAddress, hashIpAddress, hashNetworkAddress } from "../../src/services/security/networkIdentity.service.js";

describe("Network identity", () => {
  it("canonicalizes equivalent IPv6 and mapped IPv4 representations", () => {
    expect(hashIpAddress("2001:db8::1")).toBe(hashIpAddress("2001:0db8:0:0:0:0:0:1"));
    expect(hashIpAddress("::ffff:192.0.2.1")).toBe(hashIpAddress("192.0.2.1"));
    expect(canonicalAddress("::ffff:c000:201")).toBe("192.0.2.1");
  });
  it("shares only the IPv6 /64 budget while retaining distinct host signals", () => {
    expect(hashNetworkAddress("2001:db8:1:2::1")).toBe(hashNetworkAddress("2001:db8:1:2::abcd"));
    expect(hashIpAddress("2001:db8:1:2::1")).not.toBe(hashIpAddress("2001:db8:1:2::abcd"));
    expect(hashNetworkAddress("2001:db8:1:2::1")).not.toBe(hashNetworkAddress("2001:db8:1:3::1"));
    expect(hashNetworkAddress("192.0.2.1")).toBeUndefined();
  });
});
