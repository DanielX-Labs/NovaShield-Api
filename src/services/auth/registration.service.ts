import mongoose, { Types, type ClientSession } from "mongoose";
import { env } from "../../config/env.js";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { PasswordHistoryModel } from "../../models/PasswordHistory.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { AppError } from "../../utils/AppError.js";
import { normalizeEmail } from "../../utils/email.js";
import { createPasswordHash } from "../password/password.service.js";
import { generateOtp, hashOtp, verifyOtpHash } from "../otp/otp.service.js";
import { sendVerificationOtpEmail } from "../email/email.service.js";
import {
  recordSecurityEvent,
  type SecurityContext,
} from "../security/securityEvent.service.js";

// SMTP is injectable; tests exercise real MongoDB writes without sending mail.
export interface RegistrationDependencies {
  sendOtp(email: string, otp: string): Promise<void>;
  createHash(password: string, context: { email: string; name?: string }): Promise<string>;
}

const defaults: RegistrationDependencies = {
  sendOtp: sendVerificationOtpEmail,
  createHash: createPasswordHash,
};

function invalidOtp(): AppError {
  return new AppError(
    "The verification code is invalid or expired.",
    400,
    "OTP_INVALID",
  );
}

export function createRegistrationService(
  dependencies: RegistrationDependencies = defaults,
) {
  // Transactions deliberately have no non-transactional fallback.
  async function transact<T>(
    work: (session: ClientSession) => Promise<T>,
  ): Promise<T> {
    try {
      return await mongoose.connection.transaction(work);
    } catch (error) {
      if (error instanceof AppError) throw error;
      if ((error as { code?: number }).code === 11000) throw error;
      throw new AppError(
        "Registration is temporarily unavailable. Please try again.",
        503,
        "AUTH_UNAVAILABLE",
      );
    }
  }

  async function createChallenge(
    userId: Types.ObjectId,
    email: string,
    id: Types.ObjectId,
    otp: string,
    session: ClientSession,
  ): Promise<void> {
    // Replacing a challenge invalidates all previous verification codes.
    await OtpChallengeModel.updateMany(
      { userId, purpose: "EMAIL_VERIFICATION", consumedAt: { $exists: false } },
      { $set: { consumedAt: new Date() } },
      { session },
    );
    await OtpChallengeModel.create([{
      _id: id,
      userId,
      purpose: "EMAIL_VERIFICATION",
      otpHash: hashOtp(otp, id.toHexString()),
      target: email,
      expiresAt: new Date(Date.now() + env.OTP_TTL_MINUTES * 60_000),
      maxAttempts: env.OTP_MAX_ATTEMPTS,
    }], { session });
  }

  async function deliver(
    userId: Types.ObjectId,
    email: string,
    challengeId: Types.ObjectId,
    otp: string,
    context: SecurityContext,
    resent = false,
  ): Promise<void> {
    try {
      // SMTP must never run inside a transaction callback that MongoDB may retry.
      await dependencies.sendOtp(email, otp);
    } catch {
      await transact(async (session) => {
        await OtpChallengeModel.updateOne(
          { _id: challengeId },
          { $set: { consumedAt: new Date() } },
          { session },
        );
        await recordSecurityEvent(
          "AUTH_EMAIL_DELIVERY_FAILURE", context, userId, session, "LOW",
        );
      });
      throw new AppError(
        "Verification email could not be sent. Please request a new code later.",
        503,
        "EMAIL_DELIVERY_UNAVAILABLE",
      );
    }
    // Provider acceptance does not imply delivery to the recipient's inbox.
    await recordSecurityEvent(
      resent ? "AUTH_EMAIL_OTP_RESENT" : "AUTH_EMAIL_OTP_SENT",
      context,
      userId,
    );
  }

  async function register(
    input: { email: string; password: string; name?: string },
    context: SecurityContext,
  ): Promise<{ challengeId: string }> {
    const email = normalizeEmail(input.email);
    // Run policy, breach screening and hashing before checking account existence.
    const passwordHash = await dependencies.createHash(input.password, {
      email,
      ...(input.name ? { name: input.name } : {}),
    });
    const userId = new Types.ObjectId();
    const challengeId = new Types.ObjectId();
    const otp = generateOtp();
    let created: boolean;

    try {
      created = await transact(async (session) => {
        if (await AuthUserModel.exists({ emailNormalized: email }).session(session)) {
          return false;
        }
        await AuthUserModel.create([{
          _id: userId,
          email,
          emailNormalized: email,
          verificationOtpIssuedAt: new Date(),
        }], { session });
        await CredentialModel.create([{ userId, passwordHash }], { session });
        // Seed history with the initial password so it cannot be reused later.
        await PasswordHistoryModel.create([{ userId, passwordHash }], { session });
        await createChallenge(userId, email, challengeId, otp, session);
        await recordSecurityEvent("AUTH_REGISTERED", context, userId, session);
        return true;
      });
    } catch (error) {
      // A concurrent registration losing the unique-email race is a duplicate.
      if ((error as { code?: number }).code !== 11000) throw error;
      created = false;
    }
    if (created) await deliver(userId, email, challengeId, otp, context);

    // Duplicate registration never changes credentials or exposes account status.
    return { challengeId: challengeId.toHexString() };
  }

  async function resend(
    emailInput: string,
    context: SecurityContext,
  ): Promise<{ challengeId: string }> {
    const email = normalizeEmail(emailInput);
    const challengeId = new Types.ObjectId();
    const otp = generateOtp();
    const userId = await transact(async (session) => {
      // Updating the user serializes resend against verification and other resends.
      const user = await AuthUserModel.findOneAndUpdate({
        emailNormalized: email,
        status: "PENDING_VERIFICATION",
        isEmailVerified: false,
        $or: [
          { verificationOtpIssuedAt: { $exists: false } },
          { verificationOtpIssuedAt: {
            $lte: new Date(Date.now() - env.OTP_RESEND_COOLDOWN_SECONDS * 1000),
          } },
        ],
      }, {
        $set: { verificationOtpIssuedAt: new Date() },
      }, { returnDocument: "after", session });
      if (!user) return null;
      await createChallenge(user._id, email, challengeId, otp, session);
      return user._id;
    });
    if (userId) await deliver(userId, email, challengeId, otp, context, true);
    return { challengeId: challengeId.toHexString() };
  }

  async function verify(
    challengeId: string,
    otp: string,
    context: SecurityContext,
  ): Promise<void> {
    const verified = await transact(async (session) => {
      // Claim an attempt atomically before comparing; expiry is checked by the app.
      const challenge = await OtpChallengeModel.findOneAndUpdate({
        _id: challengeId,
        purpose: "EMAIL_VERIFICATION",
        consumedAt: { $exists: false },
        expiresAt: { $gt: new Date() },
        $expr: { $lt: ["$attempts", "$maxAttempts"] },
      }, {
        $inc: { attempts: 1 },
      }, { returnDocument: "after", session })
        .select("+otpHash +target +attempts +maxAttempts");
      if (!challenge) return false;

      if (!verifyOtpHash(otp, challengeId, challenge.otpHash)) {
        await recordSecurityEvent(
          "AUTH_EMAIL_OTP_FAILURE", context, challenge.userId, session, "LOW",
        );
        // Return rather than throw, so the failed attempt is committed.
        return false;
      }

      const user = await AuthUserModel.findOneAndUpdate({
        _id: challenge.userId,
        emailNormalized: challenge.target,
        status: "PENDING_VERIFICATION",
        isEmailVerified: false,
      }, {
        $set: { isEmailVerified: true, status: "ACTIVE" },
      }, { returnDocument: "after", session });
      if (!user) return false;

      await OtpChallengeModel.updateMany(
        { userId: user._id, purpose: "EMAIL_VERIFICATION",
          consumedAt: { $exists: false } },
        { $set: { consumedAt: new Date() } },
        { session },
      );
      await recordSecurityEvent("AUTH_EMAIL_VERIFIED", context, user._id, session);
      return true;
    });
    if (!verified) throw invalidOtp();
  }

  return { register, resend, verify };
}

export const registrationService = createRegistrationService();
