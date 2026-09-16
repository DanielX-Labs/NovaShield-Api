import { beforeEach, describe, expect, it, vi } from "vitest";
const database = vi.hoisted(() => ({ command: vi.fn(), readyState: 1 }));
vi.mock("mongoose", () => ({ default: { connection: {
  get readyState() { return database.readyState; }, db: { command: database.command },
} } }));
vi.mock("../../src/config/env.js", () => ({ env: {} }));
vi.mock("../../src/config/logger.js", () => ({ logger: {} }));
vi.mock("../../src/config/authStorage.js", () => ({ initializeAuthStorage: vi.fn() }));
beforeEach(() => {
  vi.resetModules();
  database.readyState = 1;
  database.command.mockReset().mockResolvedValue({ ok: 1 });
});

describe("Readiness", () => {
  it("pings the database with a bounded timeout", async () => {
    const { isDatabaseReady } = await import("../../src/config/database.js");
    expect(await isDatabaseReady()).toBe(true);
    expect(database.command).toHaveBeenCalledWith({ ping: 1 }, { timeoutMS: 1500 });
    database.command.mockRejectedValue(new Error("unreachable"));
    expect(await isDatabaseReady()).toBe(false);
  });
  it("fails while disconnected or draining", async () => {
    const { isDatabaseReady, markDatabaseDraining } = await import("../../src/config/database.js");
    database.readyState = 0;
    expect(await isDatabaseReady()).toBe(false);
    database.readyState = 1;
    markDatabaseDraining();
    expect(await isDatabaseReady()).toBe(false);
    expect(database.command).not.toHaveBeenCalled();
  });
});
