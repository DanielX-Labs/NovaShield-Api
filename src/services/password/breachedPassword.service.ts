import { createHash } from "node:crypto";
import { env } from "../../config/env.js";
import {
  BreachedPasswordServiceError,
  type BreachedPasswordResult,
} from "./breachedPassword.types.js";

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range";

// SHA-1 is temporary lookup material only; password storage uses Argon2id.
function createSha1(value: string): string {
  return createHash("sha1")
    .update(value, "utf8")
    .digest("hex")
    .toUpperCase();
}

function findHashSuffix(body: string, expectedSuffix: string): number {
  let occurrenceCount = 0;
  const lines = body.trim().split(/\r?\n/u);

  // Malformed responses are outages, never evidence of a clean password.
  for (const line of lines) {
    const match = /^([A-F0-9]{35}):(\d+)$/iu.exec(line.trim());
    const count = Number(match?.[2]);
    if (!match || !Number.isSafeInteger(count) || count < 0) {
      throw new BreachedPasswordServiceError(
        "Password breach service returned an invalid response.",
      );
    }
    if (match[1]?.toUpperCase() === expectedSuffix) {
      occurrenceCount = Math.max(occurrenceCount, count);
    }
  }
  // Padding rows have zero occurrences and therefore do not indicate a breach.
  return occurrenceCount;
}

export async function checkBreachedPassword(
  password: string,
): Promise<BreachedPasswordResult> {
  if (!env.BREACHED_PASSWORD_CHECK_ENABLED) {
    return { breached: false, occurrenceCount: 0, checked: false };
  }

  // Bound work even if a caller bypasses the high-level password service.
  if (!password || password.length > env.PASSWORD_MAX_LENGTH) {
    throw new BreachedPasswordServiceError(
      "Password length is outside screening limits.",
    );
  }

  const sha1 = createSha1(password);
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    env.BREACHED_PASSWORD_TIMEOUT_MS,
  );

  try {
    // Only the five-character prefix leaves NovaShield. Never log lookup data.
    const response = await fetch(`${HIBP_RANGE_URL}/${prefix}`, {
      method: "GET",
      headers: {
        "User-Agent": "NovaShield-Authentication-Security-Service",
        "Add-Padding": "true",
      },
      signal: controller.signal,
      redirect: "error",
    });
    if (!response.ok) {
      throw new BreachedPasswordServiceError(
        `Password breach service returned HTTP ${response.status}.`,
      );
    }

    // The timeout remains active while reading the body as well.
    const occurrenceCount = findHashSuffix(await response.text(), suffix);
    return {
      breached: occurrenceCount > 0,
      occurrenceCount,
      checked: true,
    };
  } catch (error) {
    if (error instanceof BreachedPasswordServiceError) throw error;
    throw new BreachedPasswordServiceError(
      "Password breach screening is temporarily unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
}
