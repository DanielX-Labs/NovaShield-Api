import mongoose, { Types, type ClientSession } from "mongoose";
import { randomBytes } from "node:crypto";
import { env } from "../../config/env.js";
import { logger } from "../../config/logger.js";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { CredentialModel } from "../../models/Credential.model.js";
import { AbuseBucketModel } from "../../models/AbuseBucket.model.js";
import { createOtpChallenge } from "../otp/otpChallenge.service.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { AppError } from "../../utils/AppError.js";
import { normalizeEmail } from "../../utils/email.js";
import { createPasswordHash } from "../password/password.service.js";
import { generateOtp, verifyOtpHash } from "../otp/otp.service.js";
import { enqueueEmail } from "../email/emailOutbox.service.js";
import {
  recordSecurityEvent,
  type SecurityContext,
} from "../security/securityEvent.service.js";

// Password assessment is injectable; email delivery uses the transactional outbox.
export interface RegistrationDependencies {
  createHash(password: string, context: { email: string; name?: string }): Promise<string>;
}

const defaults: RegistrationDependencies = {
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
      logger.error({ err: error, operation: "auth.registration" }, "Registration transaction failed");
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
    // Share challenge storage rules while preserving verification-specific defaults.
    await createOtpChallenge({
      userId, purpose: "EMAIL_VERIFICATION", target: email,
      challengeId: id, otp,
    }, session);
  }

  // Count actual emails, not anonymous requests. Call only while holding the user lock.
  async function reserveEmail(userId: Types.ObjectId, session: ClientSession): Promise<boolean> {
    const windowMs = 15 * 60_000;
    const window = Math.floor(Date.now() / windowMs);
    const id = `verification-issued:${userId.toHexString()}:${window}`;
    const bucket = await AbuseBucketModel.findById(id).session(session);
    if (bucket && bucket.count >= 5) return false;
    await AbuseBucketModel.updateOne({ _id: id }, {
      $inc: { count: 1 },
      $setOnInsert: { expiresAt: new Date((window + 2) * windowMs) },
    }, { upsert: true, session });
    return true;
  }

  async function register(
    input: { email: string; password: string; name?: string },
    context: SecurityContext,
  ): Promise<void> {
    const email = normalizeEmail(input.email);
    // Run policy, breach screening and hashing before checking account existence.
    const passwordHash = await dependencies.createHash(input.password, {
      email,
      ...(input.name ? { name: input.name } : {}),
    });
    const userId = new Types.ObjectId();
    const challengeId = new Types.ObjectId(randomBytes(12));
    const otp = generateOtp();

    try {
      await transact(async (session) => {
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
        await reserveEmail(userId, session);
        // History starts empty; only replaced credentials belong there.
        await createChallenge(userId, email, challengeId, otp, session);
        await enqueueEmail({ userId, email, challengeId, otp, kind: "VERIFY",
          expiresAt: new Date(Date.now() + env.OTP_TTL_MINUTES * 60_000), requestId: context.requestId }, session);
        await recordSecurityEvent("AUTH_REGISTERED", context, userId, session);
        return true;
      });
    } catch (error) {
      // A concurrent registration losing the unique-email race is a duplicate.
      if ((error as { code?: number }).code !== 11000) throw error;
    }


    // Only the mailbox receives the proof locator; anonymous callers learn nothing.
  }

  async function resend(
    emailInput: string,
    context: SecurityContext,
  ): Promise<void> {
    const email = normalizeEmail(emailInput);
    const challengeId = new Types.ObjectId(randomBytes(12));
    const otp = generateOtp();
    await transact(async (session) => {
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
      // Preserve a usable mailbox proof even if a different client requests resend.
      const outstanding = await OtpChallengeModel.exists({
        userId: user._id,
        purpose: "EMAIL_VERIFICATION",
        verificationProtocolVersion: 2,
        consumedAt: { $exists: false },
        expiresAt: { $gt: new Date() },
        $expr: { $lt: ["$attempts", "$maxAttempts"] },
      }).session(session);
      if (outstanding) return null;
      // Exhausting delivery quota never returns an account-specific HTTP error.
      if (!await reserveEmail(user._id, session)) return null;
      await createChallenge(user._id, email, challengeId, otp, session);
      await enqueueEmail({ userId: user._id, email, challengeId, otp, kind: "RESEND",
        expiresAt: new Date(Date.now() + env.OTP_TTL_MINUTES * 60_000), requestId: context.requestId }, session);
      return user._id;
    });
  }

  async function verify(
    challengeId: string,
    otp: string,
    context: SecurityContext,
    password: string,
  ): Promise<void> {
    // Reserve a bounded attempt before performing password policy or hashing work.
    const proof = await transact(async (session) => {
      // Claim an attempt atomically before comparing; expiry is checked by the app.
      const challenge = await OtpChallengeModel.findOneAndUpdate({
        _id: challengeId,
        purpose: "EMAIL_VERIFICATION",
        verificationProtocolVersion: 2,
        consumedAt: { $exists: false },
        expiresAt: { $gt: new Date() },
        $expr: { $lt: ["$attempts", "$maxAttempts"] },
      }, {
        $inc: { attempts: 1 },
      }, { returnDocument: "after", session })
        .select("+otpHash +target +attempts +maxAttempts");
      if (!challenge) return null;

      if (!verifyOtpHash(otp, challengeId, challenge.otpHash)) {
        await recordSecurityEvent(
          "AUTH_EMAIL_OTP_FAILURE", context, challenge.userId, session, "LOW",
        );
        // Return rather than throw, so the failed attempt is committed.
        return null;
      }

      return { id: challenge._id, userId: challenge.userId, email: challenge.target };
    });
    if (!proof) throw invalidOtp();

    // Mailbox ownership authorizes THIS password, never the pre-registration hash.
    // Keep external screening and Argon2 outside retryable MongoDB transactions.
    const passwordHash = await dependencies.createHash(password, { email: proof.email });
    const verified = await transact(async (session) => {
      const consumed = await OtpChallengeModel.findOneAndUpdate({
        _id: proof.id, userId: proof.userId,
        purpose: "EMAIL_VERIFICATION", verificationProtocolVersion: 2,
        consumedAt: { $exists: false }, expiresAt: { $gt: new Date() },
      }, { $set: { consumedAt: new Date() } }, {
        returnDocument: "after", session,
      });
      if (!consumed) return false;

      const user = await AuthUserModel.findOneAndUpdate({
        _id: proof.userId,
        emailNormalized: proof.email,
        status: "PENDING_VERIFICATION",
        isEmailVerified: false,
      }, {
        $set: { isEmailVerified: true, status: "ACTIVE" },
      }, { returnDocument: "after", session });
      if (!user) return false;

      // Replace legacy/pending credentials atomically with identity activation.
      await CredentialModel.updateOne({ userId: user._id }, {
        $set: { passwordHash, lastChangedAt: new Date() },
        $inc: { passwordVersion: 1 },
      }, { upsert: true, session });

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
