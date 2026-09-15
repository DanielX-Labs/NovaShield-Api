import { assessLoginAbuse, recordAuthAttempt } from "../security/authAbuse.service.js";
import { delay } from "../../utils/delay.js";
import mongoose from "mongoose";
import { AuthUserModel } from "../../models/AuthUser.model.js";
import { env } from "../../config/env.js";
import { normalizeEmail } from "../../utils/email.js";
import { AppError } from "../../utils/AppError.js";
import { validatePassword } from "../password/password.service.js";
import { performDummyPasswordVerification } from "../password/dummyPassword.service.js";
import { getCredentialForAuthentication } from "./credential.service.js";
import { createSession } from "../session/session.service.js";
import {
  recordSecurityEvent,
  type SecurityContext,
} from "../security/securityEvent.service.js";

export interface LoginInput {
  email: string;
  password: string;
  requestId?: string;
  userAgent?: string;
  ipHash?: string;
}

function invalidCredentials(): AppError {
  return new AppError("Invalid email or password.", 401, "INVALID_CREDENTIALS");
}

export async function loginUser(input: LoginInput) {
  // Defense in depth for internal callers bypassing HTTP validation.
  if (!input.password || input.password.length > env.PASSWORD_MAX_LENGTH) {
    throw invalidCredentials();
  }
  const context: SecurityContext = {
    requestId: input.requestId ?? "",
    ipHash: input.ipHash ?? "",
    ...(input.userAgent ? { userAgent: input.userAgent.slice(0, 512) } : {}),
  };

  const email = normalizeEmail(input.email);
  const attemptContext = { email, ...(input.ipHash ? { ipHash: input.ipHash } : {}) };
  try {
    // Assessment precedes account lookup and expensive password verification.
    const abuse = await assessLoginAbuse(attemptContext);
    if (abuse.suspicious || abuse.blocked) {
      await mongoose.connection.transaction(async (session) => {
        if (abuse.suspicious) {
          await recordSecurityEvent(
            "AUTH_SUSPICIOUS_LOGIN", context, undefined, session,
            abuse.score >= 80 ? "HIGH" : "MEDIUM", abuse,
          );
        }
        if (abuse.blocked) {
          await recordAuthAttempt({
            ...attemptContext, outcome: "BLOCKED", reason: "RATE_LIMITED",
          }, session);
          await recordSecurityEvent(
            "AUTH_RATE_LIMITED", context, undefined, session, "MEDIUM", abuse,
          );
        }
      });
    }
    // Refusals do not add failures or prolong the rolling failure window.
    if (abuse.blocked) {
      throw new AppError(
        "Too many authentication attempts. Please try again later.",
        429, "AUTH_RATE_LIMITED",
      );
    }
    if (abuse.delayMs > 0) await delay(abuse.delayMs);
    const user = await AuthUserModel.findOne({
      emailNormalized: email,
    });
    const credential = user
      ? await getCredentialForAuthentication(user._id)
      : null;

    if (!user || !credential) {
      // Both unknown identities and missing credentials perform Argon2 work.
      await performDummyPasswordVerification(input.password);
      await mongoose.connection.transaction(async (session) => {
        await recordAuthAttempt({
          ...attemptContext,
          ...(user ? { userId: user._id.toHexString() } : {}),
          outcome: "FAILURE", reason: "INVALID_CREDENTIALS",
        }, session);
        await recordSecurityEvent(
          "AUTH_LOGIN_FAILURE", context, user?._id, session, "LOW",
        );
      });
      throw invalidCredentials();
    }

    const matches = await validatePassword(credential.passwordHash, input.password);
    if (!matches) {
      // Atomic increments preserve failures even when multiple attempts overlap.
      await mongoose.connection.transaction(async (session) => {
        await recordAuthAttempt({
          ...attemptContext, userId: user._id.toHexString(),
          outcome: "FAILURE", reason: "INVALID_CREDENTIALS",
        }, session);
        const failedUser = await AuthUserModel.findByIdAndUpdate(user._id, {
          $inc: { failedLoginCount: 1 },
          $set: { lastFailedLoginAt: new Date() },
        }, { returnDocument: "after", session }).select("+failedLoginCount");
        await recordSecurityEvent(
          "AUTH_LOGIN_FAILURE", context, user._id, session,
          (failedUser?.failedLoginCount ?? 0) >= 5 ? "MEDIUM" : "LOW",
        );
      });
      throw invalidCredentials();
    }

    // Recheck identity state and the credential after expensive verification.
    // Updating AuthUser serializes login against account-state changes.
    const result = await mongoose.connection.transaction(async (session) => {
      const currentCredential = await getCredentialForAuthentication(user._id, session);
      if (!currentCredential
        || currentCredential.passwordVersion !== credential.passwordVersion
        || currentCredential.passwordHash !== credential.passwordHash) {
        await recordAuthAttempt({
          ...attemptContext, userId: user._id.toHexString(),
          outcome: "FAILURE", reason: "INVALID_CREDENTIALS",
        }, session);
        await recordSecurityEvent(
          "AUTH_LOGIN_FAILURE", context, user._id, session, "LOW",
        );
        return null;
      }

      const activeUser = await AuthUserModel.findOneAndUpdate({
        _id: user._id,
        status: "ACTIVE",
        isEmailVerified: true,
      }, {
        $set: { failedLoginCount: 0, lastSuccessfulLoginAt: new Date() },
      }, { returnDocument: "after", session });
      if (!activeUser) {
        await recordAuthAttempt({
          ...attemptContext, userId: user._id.toHexString(),
          outcome: "FAILURE", reason: "ACCOUNT_NOT_AVAILABLE",
        }, session);
        await recordSecurityEvent(
          "AUTH_LOGIN_FAILURE", context, user._id, session, "LOW",
        );
        return { unavailable: true as const };
      }

      const tokens = await createSession({
        userId: user._id,
        passwordVersion: currentCredential.passwordVersion,
        ...(input.userAgent ? { userAgent: input.userAgent.slice(0, 512) } : {}),
        ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      }, session);
      // Preserve past failures: success is evidence, not a telemetry reset.
      await recordAuthAttempt({
        ...attemptContext, userId: user._id.toHexString(),
        outcome: "SUCCESS", reason: "SUCCESS",
      }, session);
      await recordSecurityEvent(
        "AUTH_LOGIN_SUCCESS",
        { ...context, sessionId: tokens.sessionId },
        user._id,
        session,
        "INFO",
        abuse,
      );
      return { userId: user._id.toHexString(), ...tokens };
    });

    if (!result) throw invalidCredentials();
    if ("unavailable" in result) {
      throw new AppError(
        "Authentication cannot be completed for this account.",
        403,
        "ACCOUNT_NOT_AVAILABLE",
      );
    }
    return result;
  } catch (error) {
    if (error instanceof AppError) throw error;
    // Do not expose database errors, hashes, or token material to logs or callers.
    throw new AppError(
      "Authentication is temporarily unavailable.",
      503,
      "AUTH_UNAVAILABLE",
    );
  }
}
