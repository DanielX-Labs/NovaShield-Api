import { describe, expect, it, vi } from "vitest";
vi.mock("../../src/config/env.js", () => ({ env: { APP_NAME: "test", NODE_ENV: "test" } }));
import { createLogger } from "../../src/config/logger.js";
import { safeRequestPath } from "../../src/middleware/httpLogger.middleware.js";

describe("Log privacy", () => {
  it("preserves safe failure categories and operation names without arbitrary text", () => {
    const output: string[] = [];
    const logger = createLogger({ write: line => { output.push(line); } });
    logger.error({ operation: "email.send", err: {
      name: "Error", code: "EAUTH", message: "smtp-secret", response: "private-recipient",
    } }, "SMTP failed");
    expect(JSON.parse(output[0]!)).toMatchObject({
      operation: "email.send", err: { category: "EMAIL", code: "EAUTH", type: "Error" },
    });
    logger.error({ operation: "secret-operation", err: {
      name: "private-name", code: "private-code", cause: "private-cause",
    } }, "Failure");
    logger.error({ operation: "http.request", err: new TypeError("private-stack") }, "Failure");
    logger.error({ operation: "database.connect", err: { name: "MongoServerError", code: 11000 } }, "Failure");
    expect(JSON.parse(output[2]!).err.category).toBe("PROGRAMMING");
    expect(JSON.parse(output[3]!).err.code).toBe("DUPLICATE_KEY");
    expect(output.join("")).not.toMatch(/private-|smtp-secret|secret-operation/u);
  });
  it("redacts credential fields and suppresses third-party error payloads", () => {
    const output: string[] = [];
    const logger = createLogger({ write: line => { output.push(line); } });
    logger.error({ password: "secret-one", passwordHash: "secret-two",
      err: new Error("smtp://user:secret-three@host"), payload: "secret-four",
      req: { headers: { authorization: "secret-five", cookie: "secret-six" } },
    }, "Operation failed");
    for (const value of ["one", "two", "three", "four", "five", "six"]) {
      expect(output.join("")).not.toContain(`secret-${value}`);
    }
  });
  it("removes query strings and unknown path material", () => {
    expect(safeRequestPath("/api/v1/auth/login?password=secret")).toBe("/api/v1/auth/login");
    expect(safeRequestPath("/secret-value")).toBe("[unmatched]");
    expect(safeRequestPath("/api/v1/auth/sessions/secret-value")).toBe("/api/v1/auth/sessions/:sessionId");
  });
});
