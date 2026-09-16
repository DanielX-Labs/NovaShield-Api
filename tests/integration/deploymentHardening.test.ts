import {
  seedActiveUser, login, email, password, requestReset, resetCode, confirmReset,
  external, replacementPassword,
} from "../helpers/authIntegration.js";
import { describe, it, expect } from "vitest";
import request from "supertest";
import type { Response as TestResponse } from "supertest";
import { randomUUID } from "node:crypto";
import { Types } from "mongoose";
import { app } from "../../src/app.js";
import { env } from "../../src/config/env.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { OtpChallengeModel } from "../../src/models/OtpChallenge.model.js";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { EmailOutboxModel } from "../../src/models/EmailOutbox.model.js";
import { loginUser } from "../../src/services/auth/login.service.js";
import { requestPasswordReset } from "../../src/services/password/passwordReset.service.js";

describe("Deployment hardening regressions", () => {
  it("retires legacy reset challenges and permits a fresh protocol-v2 request", async () => {
    await seedActiveUser();
    await requestReset();
    await OtpChallengeModel.updateMany({}, { $unset: { resetProtocolVersion: 1 } });
    expect((await confirmReset()).body.error.code).toBe("PASSWORD_RESET_INVALID");
    await AuthUserModel.updateMany({}, { $set: { passwordResetOtpIssuedAt: new Date(0) } });
    expect((await requestReset()).status).toBe(202);
    expect(external.sendResetOtp).toHaveBeenCalledTimes(2);
    expect((await confirmReset()).status).toBe(200);
  });
  it("does not let a known email or guessed locator consume the owner's OTP attempts", async () => {
    await seedActiveUser();
    const issued = await requestReset();
    const challenge = await OtpChallengeModel.findOne();
    expect(issued.text).not.toContain(challenge!._id.toHexString());
    expect(external.sendResetOtp.mock.calls[0]?.[3]).toBe(challenge!._id.toHexString());
    for (let i = 0; i < 3; i += 1) {
      const denied = await request(app).post("/api/v1/password/reset/confirm").send({
        email, otp: resetCode(), challengeId: new Types.ObjectId().toHexString(),
        newPassword: replacementPassword,
      });
      expect(denied.status).toBe(400);
    }
    expect((await OtpChallengeModel.findById(challenge!._id).select("+attempts"))?.attempts).toBe(0);
    expect((await confirmReset()).status).toBe(200);
  });

  it("preserves a live challenge when strangers request another reset after cooldown", async () => {
    await seedActiveUser();
    await requestReset();
    const challenge = await OtpChallengeModel.findOne();
    await AuthUserModel.updateMany({}, { $set: { passwordResetOtpIssuedAt: new Date(0) } });
    expect((await requestReset()).status).toBe(202);
    expect(external.sendResetOtp).toHaveBeenCalledTimes(1);
    expect(await OtpChallengeModel.countDocuments()).toBe(1);
    expect((await OtpChallengeModel.findById(challenge!._id).select("+consumedAt"))?.consumedAt).toBeUndefined();
    expect((await confirmReset()).status).toBe(200);
  });

  it("counts actual reset issuance and keeps exhausted issuance responses generic", async () => {
    await seedActiveUser();
    for (let i = 0; i < env.PASSWORD_RESET_REQUEST_LIMIT; i += 1) {
      await AuthUserModel.updateMany({}, { $set: { passwordResetOtpIssuedAt: new Date(0) } });
      await OtpChallengeModel.updateMany({}, { $set: { expiresAt: new Date(0) } });
      await requestPasswordReset({ email });
    }
    await AuthUserModel.updateMany({}, { $set: { passwordResetOtpIssuedAt: new Date(0) } });
    await OtpChallengeModel.updateMany({}, { $set: { expiresAt: new Date(0) } });
    expect((await requestReset()).status).toBe(202);
    expect(await EmailOutboxModel.countDocuments({ kind: "RESET" })).toBe(env.PASSWORD_RESET_REQUEST_LIMIT);
  });

  it("paginates only owned active sessions and rejects invalid page parameters", async () => {
    const user = await seedActiveUser();
    const authenticated = await login();
    const access = authenticated.body.data.accessToken;
    await SessionModel.insertMany(Array.from({ length: 5 }, () => ({
      userId: user._id, sessionId: randomUUID(), passwordVersion: 1,
      expiresAt: new Date(Date.now() + 600_000),
    })));
    await SessionModel.create({ userId: new Types.ObjectId(), sessionId: randomUUID(),
      passwordVersion: 1, expiresAt: new Date(Date.now() + 600_000) });
    const seen: string[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < 4; page += 1) {
      const result: TestResponse = await request(app).get("/api/v1/auth/sessions")
        .query({ limit: 2, ...(cursor ? { cursor } : {}) })
        .set("Authorization", `Bearer ${access}`);
      expect(result.status).toBe(200);
      expect(result.body.data.sessions.length).toBeLessThanOrEqual(2);
      seen.push(...result.body.data.sessions.map((row: { sessionId: string }) => row.sessionId));
      cursor = result.body.data.nextCursor;
      if (!cursor) break;
    }
    expect(seen).toHaveLength(6);
    expect(new Set(seen).size).toBe(6);
    for (const query of [{ limit: 51 }, { cursor: "invalid" }, { limit: -1 }]) {
      expect((await request(app).get("/api/v1/auth/sessions").query(query)
        .set("Authorization", `Bearer ${access}`)).status).toBe(400);
    }
  });

  it("serializes concurrent logins competing for the final active-session slot", async () => {
    const previous = env.MAX_ACTIVE_SESSIONS;
    Object.assign(env, { MAX_ACTIVE_SESSIONS: 2 });
    try {
      await seedActiveUser();
      expect((await login()).status).toBe(200);
      const attempts = await Promise.allSettled([
        loginUser({ email, password, ipHash: "source-one" }),
        loginUser({ email, password, ipHash: "source-two" }),
      ]);
      expect(attempts.filter(result => result.status === "fulfilled")).toHaveLength(1);
      const refused = attempts.find(result => result.status === "rejected");
      expect(refused?.status === "rejected" && refused.reason.code).toBe("ACTIVE_SESSION_LIMIT");
      expect(await SessionModel.countDocuments()).toBe(2);
      expect(await RefreshTokenModel.countDocuments()).toBe(2);
    } finally { Object.assign(env, { MAX_ACTIVE_SESSIONS: previous }); }
  });
});
