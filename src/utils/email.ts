// Use one identity normalization rule; never apply this transformation to passwords.
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
