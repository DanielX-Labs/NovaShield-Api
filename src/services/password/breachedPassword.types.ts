// Distinguish a clean result from screening that was intentionally disabled.
export interface BreachedPasswordResult {
  breached: boolean;
  occurrenceCount: number;
  checked: boolean;
}

// Provider failures are separate from policy rejections.
export class BreachedPasswordServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BreachedPasswordServiceError";
  }
}
