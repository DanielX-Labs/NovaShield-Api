// Shared fixtures isolate each suite in its own temporary database.
import { register, sentOtp, password, models, seedActiveUser, login, email } from "../helpers/authIntegration.js";
import * as dummyPassword from "../../src/services/password/dummyPassword.service.js";
import { describe } from "vitest";
import { it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { expect } from "vitest";
import { verifyAccessToken } from "../../src/services/session/accessToken.service.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { hashRefreshToken } from "../../src/services/session/refreshTokenCrypto.service.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { vi } from "vitest";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { AbuseBucketModel } from "../../src/models/AbuseBucket.model.js";


describe("Login and session creation", () => {
  it("logs in after registration and verification, exposing refresh only in a cookie", async () => {
    const registration = await register();
    await request(app).post("/api/v1/email/verify").send({
      challengeId: registration.body.data.challengeId, otp: sentOtp(),
    });
    const response = await request(app).post("/api/v1/auth/login")
      .set("User-Agent", "NovaShield integration test")
      .send({ email: " CUSTOMER@example.com ", password });
    expect(response.status).toBe(200);
    expect(response.body.data.refreshToken).toBeUndefined();
    expect(response.body.data.expiresIn).toBe(900);
    const claims = verifyAccessToken(response.body.data.accessToken);
    expect(claims).toMatchObject({
      sub: response.body.data.userId,
      sid: response.body.data.sessionId,
      ver: 1,
      type: "access",
    });

    const cookies = response.headers["set-cookie"] as unknown as string[];
    expect(cookies).toHaveLength(1);
    const cookie = cookies[0]!;
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Path=/api/v1/auth");
    expect(cookie).toContain("SameSite=Lax");
    expect(response.headers["cache-control"]).toBe("no-store");
    const rawToken = decodeURIComponent(cookie.split(";")[0]!.split("=")[1]!);
    const session = await SessionModel.findOne().select("+ipHash").lean();
    const refresh = await RefreshTokenModel.findOne().select("+tokenHash").lean();
    expect(session).toMatchObject({
      sessionId: response.body.data.sessionId,
      userAgent: "NovaShield integration test",
    });
    expect(session!.ipHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(refresh!.sessionId.toString()).toBe(session!._id.toString());
    expect(refresh!._id.toString()).toBe(rawToken.split(".")[0]);
    expect(refresh!.tokenHash).toBe(hashRefreshToken(rawToken));
    expect(refresh!.familyId).toMatch(/^[a-f0-9-]{36}$/u);
    expect(refresh!.expiresAt.getTime()).toBe(session!.expiresAt.getTime());
    const events = await SecurityEventModel.find({ eventType: "AUTH_LOGIN_SUCCESS" }).lean();
    expect(events).toHaveLength(1);
    expect(events[0]!.sessionId).toBe(session!.sessionId);

    // Inspect raw MongoDB documents, not just projections that hide sensitive fields.
    for (const model of models) {
      const stored = JSON.stringify(await model.collection.find({}).toArray());
      for (const sensitive of [
        password, rawToken,
        "integration-test-pepper-not-a-production-secret",
        "integration-network-secret-not-for-production",
        "integration-jwt-secret-not-for-production",
      ]) expect(stored).not.toContain(sensitive);
    }
  });

  it("returns the same credential error for wrong passwords and unknown email", async () => {
    const user = await seedActiveUser();
    const wrong = await login(email, "Wrong-Cedar!Lantern-47");
    const dummy = vi.spyOn(dummyPassword, "performDummyPasswordVerification");
    const unknown = await login("unknown@example.com");
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error).toEqual(unknown.body.error);
    expect(dummy).toHaveBeenCalledWith(password);
    expect(await AuthUserModel.findById(user._id).select("+failedLoginCount"))
      .toMatchObject({ failedLoginCount: 1 });
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_FAILURE" }))
      .toBe(2);
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(wrong.headers["set-cookie"]).toBeUndefined();
  });

  it("performs dummy verification when credentials are missing", async () => {
    await AuthUserModel.create({ email, emailNormalized: email });
    const dummy = vi.spyOn(dummyPassword, "performDummyPasswordVerification");
    expect((await login()).body.error.code).toBe("INVALID_CREDENTIALS");
    expect(dummy).toHaveBeenCalledWith(password);
    expect(await SessionModel.countDocuments()).toBe(0);
  });

  it.each(["PENDING_VERIFICATION", "SUSPENDED", "DISABLED"])(
    "rejects %s accounts after password verification",
    async (status) => {
      await seedActiveUser();
      await AuthUserModel.updateMany({}, { $set: {
        status, isEmailVerified: status !== "PENDING_VERIFICATION",
      } });
      const response = await login();
      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe("ACCOUNT_NOT_AVAILABLE");
      expect(await SessionModel.countDocuments()).toBe(0);
      expect(await RefreshTokenModel.countDocuments()).toBe(0);
      expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_FAILURE" }))
        .toBe(1);
    },
  );

  it("resets failures on success and refunds successful rate-limit reservations", async () => {
    const user = await seedActiveUser();
    await login(email, "Wrong-Cedar!Lantern-47");
    expect((await login()).status).toBe(200);
    const after = await AuthUserModel.findById(user._id)
      .select("+failedLoginCount +lastFailedLoginAt").lean();
    expect(after!.failedLoginCount).toBe(0);
    expect(after!.lastSuccessfulLoginAt).toBeInstanceOf(Date);
    expect(after!.lastFailedLoginAt).toBeInstanceOf(Date);
    await expect.poll(async () => {
      const buckets = await AbuseBucketModel.find({
        _id: /^(login-ip|admit-ip|admit-pair):/u,
      }).lean();
      // Each independent source budget retains the one failure and refunds success.
      return buckets.map(bucket => bucket.count).sort();
    }, { timeout: 10_000 }).toEqual([1, 1, 1]);
  });

  it("rate limits repeated failures without permanently locking the account", async () => {
    const user = await seedActiveUser();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await login(email, "Wrong-Cedar!Lantern-47")).status).toBe(401);
    }
    const response = await login();
    expect(response.status).toBe(429);
    expect(response.headers["retry-after"]).toBeDefined();
    expect(await AuthUserModel.findById(user._id)).toMatchObject({ status: "ACTIVE" });
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_RATE_LIMITED" }))
      .toBe(1);
  });

  it("preserves concurrent failure increments", async () => {
    const user = await seedActiveUser();
    const results = await Promise.all([
      login(email, "Wrong-Cedar!Lantern-47"),
      login(email, "Wrong-Cedar!Lantern-47"),
      login(email, "Wrong-Cedar!Lantern-47"),
    ]);
    expect(results.map((result) => result.status)).toEqual([401, 401, 401]);
    expect(await AuthUserModel.findById(user._id).select("+failedLoginCount"))
      .toMatchObject({ failedLoginCount: 3 });
  });

  it("rolls back session and login state when refresh-token storage fails", async () => {
    const user = await seedActiveUser();
    vi.spyOn(RefreshTokenModel, "create")
      .mockRejectedValueOnce(new Error("Injected storage failure"));
    const response = await login();
    expect(response.status).toBe(503);
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(0);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_LOGIN_SUCCESS" }))
      .toBe(0);
    expect((await AuthUserModel.findById(user._id))!.lastSuccessfulLoginAt)
      .toBeUndefined();
  });

  it("rolls back session and refresh token when success auditing fails", async () => {
    await seedActiveUser();
    vi.spyOn(SecurityEventModel, "create")
      .mockRejectedValueOnce(new Error("Injected audit failure"));
    expect((await login()).status).toBe(503);
    expect(await SessionModel.countDocuments()).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(0);
  });

  it("rejects excessive input and untrusted browser origins", async () => {
    const excessive = await login(email, "x".repeat(129));
    expect(excessive.status).toBe(400);
    const origin = await request(app).post("/api/v1/auth/login")
      .set("Origin", "https://attacker.example")
      .send({ email, password });
    expect(origin.status).toBe(403);
    expect(origin.body.error.code).toBe("ORIGIN_NOT_ALLOWED");
    expect(await SessionModel.countDocuments()).toBe(0);
  });
});
