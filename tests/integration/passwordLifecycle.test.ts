// Shared fixtures isolate each suite in its own temporary database.
import { seedActiveUser, login, change, replacementPassword, loginFixtureHash, sessions, refresh, refreshCookie, email, external, password, thirdPassword, requestReset, resetCode, confirmReset } from "../helpers/authIntegration.js";
import { describe } from "vitest";
import { it } from "vitest";
import { expect } from "vitest";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { verifyPassword } from "../../src/services/password/passwordHash.service.js";
import { PasswordHistoryModel } from "../../src/models/PasswordHistory.model.js";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { OtpChallengeModel } from "../../src/models/OtpChallenge.model.js";
import { vi } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";


describe("Password lifecycle", () => {
  it("changes credentials, archives only the old hash and revokes all sessions", async () => {
    const user = await seedActiveUser();
    const first = await login();
    const second = await login();
    const result = await change(first.body.data.accessToken);
    expect(result.status).toBe(200);
    expect(String(result.headers["set-cookie"])).toContain("Expires=Thu, 01 Jan 1970");
    const credential = await CredentialModel.findOne({ userId: user._id }).select("+passwordHash");
    expect(credential?.passwordVersion).toBe(2);
    expect(await verifyPassword(credential!.passwordHash, replacementPassword)).toBe(true);
    const history = await PasswordHistoryModel.find().select("+passwordHash");
    expect(history.map((entry) => entry.passwordHash)).toEqual([loginFixtureHash]);
    expect((await AuthUserModel.findById(user._id))?.passwordChangedAt).toBeInstanceOf(Date);
    expect(await SessionModel.countDocuments({ revokedAt: { $exists: false } })).toBe(0);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } })).toBe(0);
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(first))).status).toBe(401);
    expect((await login()).status).toBe(401);
    expect((await login(email, replacementPassword)).status).toBe(200);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_CHANGED" })).toBe(1);
    expect(external.sendChanged).toHaveBeenCalledWith(email);
  });

  it("rejects wrong current passwords, weak replacements and the current password", async () => {
    await seedActiveUser();
    const access = (await login()).body.data.accessToken;
    expect((await change(access, "incorrect-password")).body.error.code).toBe("CURRENT_PASSWORD_INVALID");
    expect((await change(access, password, "short")).body.error.code).toBe("PASSWORD_POLICY_VIOLATION");
    expect((await change(access, password, password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
    expect(await PasswordHistoryModel.countDocuments()).toBe(0);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
    expect(external.sendChanged).not.toHaveBeenCalled();
  });

  it("keeps A and B after A to B to C, and rejects returning to A", async () => {
    await seedActiveUser();
    // Simulate a legacy registration that seeded its current hash in history.
    const credential = await CredentialModel.findOne();
    await PasswordHistoryModel.create({ userId: credential!.userId, passwordHash: loginFixtureHash });
    expect((await change((await login()).body.data.accessToken)).status).toBe(200);
    const accessB = (await login(email, replacementPassword)).body.data.accessToken;
    expect((await change(accessB, replacementPassword, thirdPassword)).status).toBe(200);
    const history = await PasswordHistoryModel.find().select("+passwordHash");
    expect(history).toHaveLength(2);
    expect(await Promise.all(history.map((entry) => verifyPassword(entry.passwordHash, thirdPassword))))
      .toEqual([false, false]);
    const accessC = (await login(email, thirdPassword)).body.data.accessToken;
    expect((await change(accessC, thirdPassword, password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
  });

  it("returns generic reset responses for unknown and unavailable accounts", async () => {
    const unknown = await requestReset();
    await seedActiveUser();
    await AuthUserModel.updateMany({}, { $set: { status: "DISABLED" } });
    const disabled = await requestReset();
    expect(unknown.status).toBe(202);
    expect(disabled.status).toBe(202);
    expect(disabled.body.message).toBe(unknown.body.message);
    expect(external.sendResetOtp).not.toHaveBeenCalled();
  });

  it("stores a bound HMAC challenge, enforces cooldown and never stores plaintext", async () => {
    await seedActiveUser();
    expect((await requestReset()).status).toBe(202);
    expect((await requestReset()).status).toBe(202);
    expect(external.sendResetOtp).toHaveBeenCalledTimes(1);
    const challenge = await OtpChallengeModel.findOne().select("+otpHash +credentialVersion +maxAttempts");
    expect(challenge?.purpose).toBe("PASSWORD_RESET");
    expect(challenge?.credentialVersion).toBe(1);
    expect(challenge?.maxAttempts).toBe(5);
    expect(challenge?.otpHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(challenge?.otpHash).not.toBe(resetCode());
    expect(challenge!.expiresAt.getTime() - challenge!.createdAt.getTime()).toBeGreaterThan(590_000);
    const stored = JSON.stringify(await OtpChallengeModel.collection.findOne({}));
    expect(stored).not.toContain(`"${resetCode()}"`);
    expect(stored).not.toContain(password);
  });

  it("resets once, revokes old tokens and accepts only the new password", async () => {
    await seedActiveUser();
    const loggedIn = await login();
    await requestReset();
    const otp = resetCode();
    expect((await confirmReset(otp)).status).toBe(200);
    expect((await confirmReset(otp)).body.error.code).toBe("PASSWORD_RESET_INVALID");
    expect((await sessions(loggedIn.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(loggedIn))).status).toBe(401);
    expect((await login()).status).toBe(401);
    expect((await login(email, replacementPassword)).status).toBe(200);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await PasswordHistoryModel.countDocuments()).toBe(1);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_RESET_COMPLETED" })).toBe(1);
  });

  it("does not consume a correct OTP when policy or breach screening rejects", async () => {
    await seedActiveUser();
    await requestReset();
    expect((await confirmReset(resetCode(), "short")).body.error.code).toBe("PASSWORD_POLICY_VIOLATION");
    external.checkBreachedPassword.mockResolvedValueOnce({ checked: true, breached: true, occurrenceCount: 1 });
    expect((await confirmReset()).body.error.code).toBe("PASSWORD_COMPROMISED");
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
    expect((await confirmReset()).status).toBe(200);
  });

  it("checks OTP knowledge before revealing current-password or history feedback", async () => {
    await seedActiveUser();
    await requestReset();
    const wrong = resetCode() === "123456" ? "654321" : "123456";
    expect((await confirmReset(wrong, password)).body.error.code).toBe("PASSWORD_RESET_INVALID");
    expect(external.checkBreachedPassword).not.toHaveBeenCalled();
    expect((await confirmReset(resetCode(), password)).body.error.code).toBe("PASSWORD_RECENTLY_USED");
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_PASSWORD_RESET_OTP_FAILURE" })).toBe(1);
  });

  it("persists the OTP attempt limit and rejects even a correct exhausted code", async () => {
    await seedActiveUser();
    await requestReset();
    const wrong = resetCode() === "123456" ? "654321" : "123456";
    for (let index = 0; index < 5; index += 1) {
      expect((await confirmReset(wrong)).status).toBe(400);
    }
    expect((await confirmReset()).body.error.code).toBe("PASSWORD_RESET_INVALID");
    const challenge = await OtpChallengeModel.findOne().select("+attempts");
    expect(challenge?.attempts).toBe(5);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
  });

  it("rejects expired and wrong-purpose challenges", async () => {
    await seedActiveUser();
    await requestReset();
    await OtpChallengeModel.updateMany({}, { $set: { purpose: "EMAIL_VERIFICATION" } });
    expect((await confirmReset()).status).toBe(400);
    await OtpChallengeModel.updateMany({}, {
      $set: { purpose: "PASSWORD_RESET", expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await confirmReset()).status).toBe(400);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
  });

  it("invalidates a reset code when an authenticated password change commits", async () => {
    await seedActiveUser();
    const access = (await login()).body.data.accessToken;
    await requestReset();
    expect((await change(access)).status).toBe(200);
    expect((await confirmReset(resetCode(), thirdPassword)).status).toBe(400);
  });

  it("commits only one concurrent use of a reset code", async () => {
    await seedActiveUser();
    await requestReset();
    const results = await Promise.all([confirmReset(), confirmReset()]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await PasswordHistoryModel.countDocuments()).toBe(1);
    expect(external.sendChanged).toHaveBeenCalledTimes(1);
  });

  it("rolls back credential, history and OTP consumption if the completion audit fails", async () => {
    await seedActiveUser();
    await requestReset();
    const createEvent = SecurityEventModel.create.bind(SecurityEventModel);
    const spy = vi.spyOn(SecurityEventModel, "create").mockImplementation((...args: any[]) => {
      if (args[0]?.[0]?.eventType === "AUTH_PASSWORD_RESET_COMPLETED") {
        return Promise.reject(new Error("test audit unavailable"));
      }
      return (createEvent as any)(...args);
    });
    expect((await confirmReset()).status).toBe(503);
    spy.mockRestore();
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(1);
    expect(await PasswordHistoryModel.countDocuments()).toBe(0);
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
    expect((await confirmReset()).status).toBe(200);
  });

  it("keeps completed changes successful when security notification delivery fails", async () => {
    await seedActiveUser();
    external.sendChanged.mockRejectedValue(new Error("SMTP unavailable"));
    expect((await change((await login()).body.data.accessToken)).status).toBe(200);
    expect((await CredentialModel.findOne())?.passwordVersion).toBe(2);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_SECURITY_NOTIFICATION_FAILURE" })).toBe(1);
  });

  it("hides reset delivery failure and retains the job for retry", async () => {
    await seedActiveUser();
    external.sendResetOtp.mockRejectedValue(new Error("SMTP unavailable"));
    expect((await requestReset()).status).toBe(202);
    expect(await OtpChallengeModel.countDocuments({ consumedAt: { $exists: false } })).toBe(1);
    expect(await SecurityEventModel.countDocuments({ eventType: "AUTH_EMAIL_DELIVERY_FAILURE" })).toBe(1);
  });

  it("requires authentication, rejects cross-site requests and bounds reset requests", async () => {
    expect((await change("invalid")).status).toBe(401);
    expect((await request(app).post("/api/v1/password/reset/request")
      .set("Origin", "https://attacker.example").send({ email })).status).toBe(403);
    for (let index = 0; index < 4; index += 1) {
      expect((await requestReset()).status).toBe(202);
    }
    expect((await requestReset()).status).toBe(429);
    expect((await request(app).post("/api/v1/password/reset/confirm")
      .send({ email, otp: "<script>", newPassword: replacementPassword })).status).toBe(400);
  });
});
