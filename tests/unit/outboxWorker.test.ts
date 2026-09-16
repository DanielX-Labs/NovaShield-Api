import { afterEach, describe, it, expect, vi } from "vitest";
const mocks = vi.hoisted(() => ({ send: vi.fn(), retention: vi.fn(), warn: vi.fn() }));
vi.mock("../../src/config/env.js", () => ({ env: {
  OUTBOX_CONCURRENCY: 2, OUTBOX_ALERT_BACKLOG: 10, OUTBOX_ALERT_AGE_SECONDS: 60,
} }));
vi.mock("../../src/services/email/emailOutbox.service.js", () => ({ processOneEmail: mocks.send }));
vi.mock("../../src/services/security/retention.service.js", () => ({ runRetention: mocks.retention }));
vi.mock("../../src/config/logger.js", () => ({ logger: { info: vi.fn(), error: vi.fn(), warn: mocks.warn } }));
vi.mock("../../src/models/EmailOutbox.model.js", () => ({ EmailOutboxModel: {
  countDocuments: async () => 20,
  findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => ({ createdAt: new Date(Date.now() - 120_000) }) }) }) }),
} }));
import { startMaintenanceWorker, reportOutboxHealth } from "../../src/services/email/outboxWorker.js";

afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); });
describe("Outbox worker scheduling", () => {
  it("drains immediately with bounded lanes and waits for in-flight work on shutdown", async () => {
    vi.useFakeTimers();
    const releases: Array<(sent: boolean) => void> = [];
    mocks.send.mockImplementation(() => new Promise<boolean>(resolve => releases.push(resolve)));
    const stop = startMaintenanceWorker();
    expect(mocks.send).toHaveBeenCalledTimes(2);
    releases[0]!(true);
    await Promise.resolve();
    expect(mocks.send).toHaveBeenCalledTimes(3);
    let stopped = false;
    const shutdown = stop().then(() => { stopped = true; });
    await Promise.resolve();
    expect(stopped).toBe(false);
    releases[1]!(true);
    releases[2]!(true);
    await shutdown;
    expect(mocks.send).toHaveBeenCalledTimes(3);
  });
  it("reports backlog and age without message contents", async () => {
    await reportOutboxHealth();
    expect(mocks.warn).toHaveBeenCalledWith(
      { pending: 20, oldestAgeSeconds: 120 }, "Email queue threshold exceeded",
    );
  });
});
