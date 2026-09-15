import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import { env } from "../../config/env.js";

const OTP_LENGTH = 6;

// randomInt avoids modulo bias; the exclusive upper bound keeps six digits.
export function generateOtp(): string {
  return randomInt(
    10 ** (OTP_LENGTH - 1),
    10 ** OTP_LENGTH,
  ).toString();
}

// Bind the OTP to its challenge and protect storage with the server secret.
export function hashOtp(otp: string, challengeId: string): string {
  return createHmac("sha256", env.AUTH_PEPPER)
    .update(`${challengeId}:${otp}`)
    .digest("hex");
}

export function verifyOtpHash(
  suppliedOtp: string,
  challengeId: string,
  storedHash: string,
): boolean {
  // Validate before decoding: Buffer.from silently truncates malformed hex.
  if (!/^\d{6}$/u.test(suppliedOtp)
    || !/^[a-f0-9]{64}$/iu.test(storedHash)) {
    return false;
  }

  const candidateBuffer = Buffer.from(
    hashOtp(suppliedOtp, challengeId),
    "hex",
  );
  const storedBuffer = Buffer.from(storedHash, "hex");

  // Equal-length digests are compared without content-dependent early returns.
  return timingSafeEqual(candidateBuffer, storedBuffer);
}
