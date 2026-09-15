declare global {
  namespace Express {
    interface Request {
      // Assigned before logging, routing, or error handling.
      id: string;
    }
  }
}

export {};
