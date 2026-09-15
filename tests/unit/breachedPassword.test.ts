import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Stub the network and configuration; npm test never contacts HIBP.
vi.mock("../../src/config/env.js", () => ({
  env: {
    BREACHED_PASSWORD_CHECK_ENABLED: true,
    BREACHED_PASSWORD_TIMEOUT_MS: 500,
    PASSWORD_MAX_LENGTH: 128,
  },
}));
import { env } from "../../src/config/env.js";
import { checkBreachedPassword } from "../../src/services/password/breachedPassword.service.js";

const fetchMock = vi.fn();
const digest = createHash("sha1").update("password").digest("hex").toUpperCase();
beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  Object.assign(env, { BREACHED_PASSWORD_CHECK_ENABLED: true });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("HIBP adapter", () => {
  it("sends only the prefix and matches the suffix locally", async () => {
    fetchMock.mockResolvedValue(new Response(digest.slice(5) + ":42\r\n"));
    await expect(checkBreachedPassword("password")).resolves.toEqual({
      checked: true, breached: true, occurrenceCount: 42,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.pwnedpasswords.com/range/" + digest.slice(0, 5),
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ "Add-Padding": "true" }),
      }),
    );
    expect(fetchMock.mock.calls[0]?.[1].body).toBeUndefined();
  });

  it.each([digest.slice(5) + ":0", "A".repeat(35) + ":9"])(
    "treats padding and absent suffixes as clean",
    async (body) => {
      fetchMock.mockResolvedValue(new Response(body));
      await expect(checkBreachedPassword("password")).resolves.toEqual({
        checked: true, breached: false, occurrenceCount: 0,
      });
    },
  );

  it.each(["", "<html>Error</html>", digest.slice(5) + ":12junk"])(
    "rejects malformed responses",
    async (body) => {
      fetchMock.mockResolvedValue(new Response(body));
      await expect(checkBreachedPassword("password"))
        .rejects.toMatchObject({ name: "BreachedPasswordServiceError" });
    },
  );

  it("handles HTTP and network failures", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 503 }));
    fetchMock.mockRejectedValueOnce(new Error("Network unavailable"));
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(checkBreachedPassword("password"))
        .rejects.toMatchObject({ name: "BreachedPasswordServiceError" });
    }
  });

  it("aborts timed-out requests and clears the timer", async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation((_url, options) => new Promise((_, reject) => {
      options.signal.addEventListener("abort", () => reject(new Error("Aborted")));
    }));
    const assertion = expect(checkBreachedPassword("password"))
      .rejects.toMatchObject({ name: "BreachedPasswordServiceError" });
    await vi.advanceTimersByTimeAsync(500);
    await assertion;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("skips the network when disabled", async () => {
    Object.assign(env, { BREACHED_PASSWORD_CHECK_ENABLED: false });
    await expect(checkBreachedPassword("password")).resolves.toEqual({
      checked: false, breached: false, occurrenceCount: 0,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
