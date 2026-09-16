// Shared fixtures isolate each suite in its own temporary database.
import { register, sentOtp, login, refreshCookie, sessions, refresh, seedActiveUser, loginFixtureHash } from "../helpers/authIntegration.js";
import { describe } from "vitest";
import { it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { expect } from "vitest";
import { RefreshTokenModel } from "../../src/models/RefreshToken.model.js";
import { SecurityEventModel } from "../../src/models/SecurityEvent.model.js";
import { AuthUserModel } from "../../src/models/AuthUser.model.js";
import { CredentialModel } from "../../src/models/Credential.model.js";
import { SessionModel } from "../../src/models/Session.model.js";
import { vi } from "vitest";
import { AbuseBucketModel } from "../../src/models/AbuseBucket.model.js";


describe("Refresh rotation and session lifecycle", () => {
  it("completes registration through rotation, then revokes the family on replay", async () => {
    const registration = await register();
    await request(app).post("/api/v1/email/verify").send({
      challengeId: registration.body.data.challengeId, otp: sentOtp(),
    });
    const initial = await login();
    const r1 = refreshCookie(initial);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    const rotated = await refresh(r1);
    expect(rotated.status).toBe(200);
    expect(rotated.body.data.refreshToken).toBeUndefined();
    const r2 = refreshCookie(rotated);
    expect(r2).not.toBe(r1);
    const tokens = await RefreshTokenModel.find()
      .select("+usedAt +replacedByTokenId +tokenHash").sort({ createdAt: 1 });
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.familyId).toBe(tokens[1]!.familyId);
    expect(tokens[0]!.usedAt).toBeInstanceOf(Date);
    expect(tokens[0]!.replacedByTokenId!.toString()).toBe(tokens[1]!._id.toString());
    expect(tokens[0]!.expiresAt).toEqual(tokens[1]!.expiresAt);
    expect((await sessions(rotated.body.data.accessToken)).status).toBe(200);

    const replay = await refresh(r1);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe("REFRESH_TOKEN_REUSED");
    expect(replay.headers["set-cookie"]?.[0]).toContain("Expires=Thu, 01 Jan 1970");
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await sessions(rotated.body.data.accessToken)).status).toBe(401);
    expect((await refresh(r2)).status).toBe(401);
    expect(await SecurityEventModel.countDocuments({
      eventType: "AUTH_REFRESH_REUSED", severity: "HIGH",
    })).toBe(1);
    const stored = JSON.stringify(await RefreshTokenModel.collection.find({}).toArray());
    expect(stored).not.toContain(decodeURIComponent(r1.split("=")[1]!));
    expect(stored).not.toContain(decodeURIComponent(r2.split("=")[1]!));
  });

  it("permits only one concurrent rotation, then treats the loser as replay", async () => {
    await seedActiveUser();
    const initial = await login();
    const r1 = refreshCookie(initial);
    const results = await Promise.all([refresh(r1), refresh(r1)]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 401]);
    expect(await RefreshTokenModel.countDocuments()).toBe(2);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    const winner = results.find((result) => result.status === 200)!;
    expect((await refresh(refreshCookie(winner))).status).toBe(401);
  });

  it("does not revoke a valid family when an attacker supplies a wrong secret", async () => {
    await seedActiveUser();
    const initial = await login();
    const r1 = refreshCookie(initial);
    const rotated = await refresh(r1);
    const raw = decodeURIComponent(r1.split("=")[1]!);
    const wrong = raw.slice(0, -1) + (raw.endsWith("A") ? "B" : "A");
    const result = await refresh("novashield_refresh=" + wrong);
    expect(result.status).toBe(401);
    expect(result.body.error.code).toBe("INVALID_REFRESH_TOKEN");
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    expect((await refresh(refreshCookie(rotated))).status).toBe(200);
  });

  it("rejects missing, malformed, unknown and expired refresh tokens", async () => {
    expect((await request(app).post("/api/v1/auth/refresh")).status).toBe(401);
    expect((await refresh("novashield_refresh=invalid")).status).toBe(401);
    expect((await refresh("novashield_refresh=" + "a".repeat(24) + "." + "A".repeat(64)))
      .status).toBe(401);
    await seedActiveUser();
    const initial = await login();
    await RefreshTokenModel.updateMany({}, {
      $set: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await refresh(refreshCookie(initial))).body.error.code)
      .toBe("REFRESH_TOKEN_EXPIRED");
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
  });

  it("requires an allowed browser origin before touching a refresh token", async () => {
    await seedActiveUser();
    const initial = await login();
    const blocked = await request(app).post("/api/v1/auth/refresh")
      .set("Cookie", refreshCookie(initial))
      .set("Origin", "https://attacker.example");
    expect(blocked.status).toBe(403);
    expect(blocked.headers["set-cookie"]).toBeUndefined();
    expect(await RefreshTokenModel.countDocuments({ usedAt: { $exists: true } })).toBe(0);
  });

  it("lists only owned active sessions and clears the cookie when revoking current", async () => {
    await seedActiveUser();
    const first = await login();
    const second = await login();
    const listed = await sessions(first.body.data.accessToken);
    expect(listed.body.data.sessions).toHaveLength(2);
    expect(listed.body.data.sessions.filter((entry: { current: boolean }) => entry.current))
      .toHaveLength(1);
    for (const entry of listed.body.data.sessions) {
      expect(entry._id).toBeUndefined();
      expect(entry.userId).toBeUndefined();
      expect(entry.ipHash).toBeUndefined();
    }
    const revokedOther = await request(app)
      .delete("/api/v1/auth/sessions/" + second.body.data.sessionId)
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(revokedOther.status).toBe(204);
    expect(revokedOther.headers["set-cookie"]).toBeUndefined();
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await sessions(first.body.data.accessToken)).body.data.sessions).toHaveLength(1);
    const revokedSelf = await request(app)
      .delete("/api/v1/auth/sessions/" + first.body.data.sessionId)
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(revokedSelf.status).toBe(204);
    expect(revokedSelf.headers["set-cookie"]).toBeDefined();
    expect((await refresh(refreshCookie(first))).status).toBe(401);
  });

  it("rejects cross-user session revocation without affecting the owner", async () => {
    await seedActiveUser();
    const owner = await login();
    const other = await AuthUserModel.create({
      email: "other@example.com", emailNormalized: "other@example.com",
      status: "ACTIVE", isEmailVerified: true,
    });
    await CredentialModel.create({ userId: other._id, passwordHash: loginFixtureHash });
    const stranger = await login("other@example.com");
    const response = await request(app)
      .delete("/api/v1/auth/sessions/" + owner.body.data.sessionId)
      .set("Authorization", "Bearer " + stranger.body.data.accessToken);
    expect(response.status).toBe(404);
    expect((await sessions(owner.body.data.accessToken)).status).toBe(200);
    expect((await sessions(stranger.body.data.accessToken)).body.data.sessions).toHaveLength(1);
  });

  it("revokes all owned sessions and cookies", async () => {
    await seedActiveUser();
    const first = await login();
    const second = await login();
    const result = await request(app).delete("/api/v1/auth/sessions")
      .set("Authorization", "Bearer " + first.body.data.accessToken);
    expect(result.status).toBe(204);
    expect(result.headers["set-cookie"]).toBeDefined();
    expect((await sessions(first.body.data.accessToken)).status).toBe(401);
    expect((await sessions(second.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(second))).status).toBe(401);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
  });

  it("logs out server-side and rejects both old access and refresh tokens", async () => {
    await seedActiveUser();
    const initial = await login();
    const result = await request(app).post("/api/v1/auth/logout")
      .set("Authorization", "Bearer " + initial.body.data.accessToken);
    expect(result.status).toBe(204);
    expect(result.headers["set-cookie"]?.[0]).toContain("HttpOnly");
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).status).toBe(401);
  });

  it("rejects disabled accounts using still-valid JWTs", async () => {
    await seedActiveUser();
    const initial = await login();
    await AuthUserModel.updateMany({}, { $set: { status: "DISABLED" } });
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).body.error.code).toBe("INVALID_SESSION");
    expect(await SessionModel.countDocuments({ revokedAt: { $exists: true } })).toBe(1);
  });

  it("does not let an old refresh token adopt a newer credential version", async () => {
    await seedActiveUser();
    const initial = await login();
    await CredentialModel.updateMany({}, { $inc: { passwordVersion: 1 } });
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
    expect((await refresh(refreshCookie(initial))).status).toBe(401);
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
  });

  it("rolls back consumption if replacement storage fails and permits retry", async () => {
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(RefreshTokenModel, "create")
      .mockRejectedValueOnce(new Error("Injected replacement failure"));
    const result = await refresh(refreshCookie(initial));
    expect(result.status).toBe(503);
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect(await RefreshTokenModel.countDocuments({ usedAt: { $exists: true } })).toBe(0);
    expect(await RefreshTokenModel.countDocuments()).toBe(1);
    expect((await refresh(refreshCookie(initial))).status).toBe(200);
  });

  it("rolls back logout if its audit event fails", async () => {
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(SecurityEventModel, "create")
      .mockRejectedValueOnce(new Error("Injected audit failure"));
    const result = await request(app).post("/api/v1/auth/logout")
      .set("Authorization", "Bearer " + initial.body.data.accessToken);
    expect(result.status).toBe(503);
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect((await sessions(initial.body.data.accessToken)).status).toBe(200);
    expect((await refresh(refreshCookie(initial))).status).toBe(200);
  });

  it("keeps logout effective when it races a rotation", async () => {
    await seedActiveUser();
    const initial = await login();
    const results = await Promise.all([
      refresh(refreshCookie(initial)),
      request(app).post("/api/v1/auth/logout")
        .set("Authorization", "Bearer " + initial.body.data.accessToken),
    ]);
    expect(results[1]!.status).toBe(204);
    expect([200, 401]).toContain(results[0]!.status);
    expect(await RefreshTokenModel.countDocuments({ revokedAt: { $exists: false } }))
      .toBe(0);
    expect((await sessions(initial.body.data.accessToken)).status).toBe(401);
  });

  it("rate limits refresh and distinguishes missing authentication from outages", async () => {
    await request(app).post("/api/v1/auth/refresh");
    await AbuseBucketModel.updateMany({ _id: /^refresh-ip:/ }, { $set: { count: 60 } });
    expect((await request(app).post("/api/v1/auth/refresh")).status).toBe(429);
    expect((await request(app).get("/api/v1/auth/sessions")).body.error.code)
      .toBe("AUTHENTICATION_REQUIRED");
    await seedActiveUser();
    const initial = await login();
    vi.spyOn(SessionModel, "findOne").mockRejectedValueOnce(new Error("Database failure"));
    expect((await sessions(initial.body.data.accessToken)).status).toBe(503);
  });
});
