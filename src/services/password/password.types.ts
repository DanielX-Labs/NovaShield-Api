// Stable codes let callers display feedback without inspecting messages.
export type PasswordIssueCode =
  | "PASSWORD_REQUIRED"
  | "PASSWORD_TOO_SHORT"
  | "PASSWORD_TOO_LONG"
  | "PASSWORD_COMMON"
  | "PASSWORD_CONTAINS_EMAIL"
  | "PASSWORD_CONTAINS_NAME"
  | "PASSWORD_REPEATED_PATTERN"
  | "PASSWORD_SEQUENTIAL_PATTERN";

export interface PasswordIssue {
  code: PasswordIssueCode;
  message: string;
}

// Context is used for assessment only and is never added to the hash.
export interface PasswordAssessmentContext {
  email?: string;
  name?: string;
}

export interface PasswordAssessmentResult {
  valid: boolean;
  issues: PasswordIssue[];
}
