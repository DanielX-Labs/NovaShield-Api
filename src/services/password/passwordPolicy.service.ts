import { env } from "../../config/env.js";
import { COMMON_PASSWORDS } from "./commonPasswords.js";
import type {
  PasswordAssessmentContext,
  PasswordAssessmentResult,
  PasswordIssue,
} from "./password.types.js";

// Normalize comparisons only; hashing preserves the exact original input.
function normalizeForComparison(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase();
}

function containsRepeatedPattern(password: string): boolean {
  // Four consecutive identical characters are easily guessed.
  return /(.)\1{3,}/u.test(password);
}

function containsSequentialPattern(password: string): boolean {
  const normalized = password.toLowerCase();
  const sequences = [
    "0123456789",
    "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop",
    "poiuytrewq",
  ];

  // Match any four-character window of the known sequences.
  return sequences.some((sequence) => {
    for (let i = 0; i <= sequence.length - 4; i += 1) {
      if (normalized.includes(sequence.slice(i, i + 4))) {
        return true;
      }
    }
    return false;
  });
}

function containsEmailContext(password: string, email?: string): boolean {
  if (!email) return false;

  // Ignore short local parts to avoid overly broad context matches.
  const localPart = normalizeForComparison(email.split("@")[0] ?? "");
  return localPart.length >= 4
    && normalizeForComparison(password).includes(localPart);
}

function containsNameContext(password: string, name?: string): boolean {
  if (!name) return false;

  const normalizedPassword = normalizeForComparison(password);
  const nameParts = normalizeForComparison(name)
    .split(/\s+/u)
    .filter((part) => part.length >= 4);

  return nameParts.some((part) => normalizedPassword.includes(part));
}

export function assessPassword(
  password: string,
  context: PasswordAssessmentContext = {},
): PasswordAssessmentResult {
  // Reject oversized input before normalization or pattern scanning.
  // Length uses JavaScript UTF-16 code units consistently across services.
  if (!password) {
    return {
      valid: false,
      issues: [{ code: "PASSWORD_REQUIRED", message: "Password is required." }],
    };
  }
  if (password.length > env.PASSWORD_MAX_LENGTH) {
    return {
      valid: false,
      issues: [{
        code: "PASSWORD_TOO_LONG",
        message: `Password must not exceed ${env.PASSWORD_MAX_LENGTH} characters.`,
      }],
    };
  }

  const issues: PasswordIssue[] = [];
  if (password.length < env.PASSWORD_MIN_LENGTH) {
    issues.push({
      code: "PASSWORD_TOO_SHORT",
      message: `Password must contain at least ${env.PASSWORD_MIN_LENGTH} characters.`,
    });
  }

  // Collect useful feedback without returning any password content.
  if (COMMON_PASSWORDS.has(normalizeForComparison(password))) {
    issues.push({
      code: "PASSWORD_COMMON",
      message: "Choose a less common password.",
    });
  }
  if (containsEmailContext(password, context.email)) {
    issues.push({
      code: "PASSWORD_CONTAINS_EMAIL",
      message: "Password must not contain a significant part of your email address.",
    });
  }
  if (containsNameContext(password, context.name)) {
    issues.push({
      code: "PASSWORD_CONTAINS_NAME",
      message: "Password must not contain your name.",
    });
  }
  if (containsRepeatedPattern(password)) {
    issues.push({
      code: "PASSWORD_REPEATED_PATTERN",
      message: "Password contains an easily guessed repeated pattern.",
    });
  }
  if (containsSequentialPattern(password)) {
    issues.push({
      code: "PASSWORD_SEQUENTIAL_PATTERN",
      message: "Password contains an easily guessed sequence.",
    });
  }

  return { valid: issues.length === 0, issues };
}
