declare global {
  namespace Express {
    interface Request {
      // Assigned before logging, routing, or error handling.
      id: string;
      // Set only after JWT and live account/session validation both succeed.
      auth?: {
        userId: string;
        sessionId: string;
        passwordVersion: number;
      };
    }
  }
}

export {};
