import type { Types } from "mongoose";
import { env } from "../../config/env.js";
import { checkBreachedPassword } from "./breachedPassword.service.js";
import { BreachedPasswordServiceError } from "./breachedPassword.types.js";
import { AppError } from "../../utils/AppError.js";
import {
  hashPassword,
  verifyPassword,
  needsPasswordRehash,
} from "./passwordHash.service.js";
import { assessPassword } from "./passwordPolicy.service.js";
import { isPasswordReused } from "./passwordHistory.service.js";
import type {
  PasswordAssessmentContext,
  PasswordAssessmentResult,
} from "./password.types.js";

// Internal assessment only; no public password-checking route is exposed.
export function assessNewPassword(
  password: string,
  context: PasswordAssessmentContext = {},
): PasswordAssessmentResult {
  return assessPassword(password, context);
}

// Keep policy enforcement consistent for creation and password changes.
function enforcePolicy(
  password: string,
  context: PasswordAssessmentContext,
): void {
  if (!assessPassword(password, context).valid) {
    throw new AppError(
      "Password does not meet security requirements.",
      400,
      "PASSWORD_POLICY_VIOLATION",
    );
  }
}

// Keep provider availability decisions outside the HIBP adapter.
async function enforceBreachedPasswordPolicy(password: string): Promise<void> {
  try {
    const result = await checkBreachedPassword(password);
    if (result.checked && result.breached) {
      throw new AppError(
        "This password has appeared in known data breaches. Choose a different password.",
        400,
        "PASSWORD_COMPROMISED",
      );
    }
  } catch (error) {
    if (!(error instanceof BreachedPasswordServiceError)) throw error;
    if (env.BREACHED_PASSWORD_FAIL_MODE === "closed") {
      throw new AppError(
        "Password security verification is temporarily unavailable. Please try again.",
        503,
        "PASSWORD_SECURITY_CHECK_UNAVAILABLE",
      );
    }
    // Fail-open mode explicitly permits an unchecked password during outages.
  }
}

export async function createPasswordHash(
  password: string,
  context: PasswordAssessmentContext = {},
): Promise<string> {
  enforcePolicy(password, context);
  await enforceBreachedPasswordPolicy(password);
  return hashPassword(password);
}

export async function validatePassword(
  passwordHash: string,
  candidatePassword: string,
): Promise<boolean> {
  return verifyPassword(passwordHash, candidatePassword);
}

export async function validatePasswordChange(
  userId: Types.ObjectId,
  newPassword: string,
  context: PasswordAssessmentContext = {},
): Promise<void> {
  // Reject invalid input before reading history or performing expensive hashes.
  enforcePolicy(newPassword, context);
  await enforceBreachedPasswordPolicy(newPassword);

  if (await isPasswordReused(userId, newPassword)) {
    throw new AppError(
      "Choose a password that has not been used recently.",
      400,
      "PASSWORD_RECENTLY_USED",
    );
  }
}

// Callers can upgrade hashes after successful authentication.
export { needsPasswordRehash };
