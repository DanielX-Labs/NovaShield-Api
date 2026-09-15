export type AuthAbuseReason =
  | "REPEATED_ACCOUNT_FAILURES"
  | "ACCOUNT_FAILURE_THRESHOLD"
  | "IP_FAILURE_THRESHOLD"
  | "POSSIBLE_PASSWORD_SPRAY"
  | "MULTI_ACCOUNT_FAILURE_PATTERN";

// These bounded, non-secret fields are also the security-event metadata contract.
export interface AuthAbuseAssessment {
  blocked: boolean;
  delayMs: number;
  suspicious: boolean;
  score: number;
  reasons: AuthAbuseReason[];
  accountFailures: number;
  ipFailures: number;
  distinctAccountsFromIp: number;
}
