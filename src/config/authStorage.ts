import mongoose from "mongoose";
import { AuthUserModel } from "../models/AuthUser.model.js";
import { CredentialModel } from "../models/Credential.model.js";
import { OtpChallengeModel } from "../models/OtpChallenge.model.js";
import { PasswordHistoryModel } from "../models/PasswordHistory.model.js";
import { SecurityEventModel } from "../models/SecurityEvent.model.js";
import { AbuseBucketModel } from "../models/AbuseBucket.model.js";
import { SessionModel } from "../models/Session.model.js";
import { RefreshTokenModel } from "../models/RefreshToken.model.js";

// Prepare collections and correctness-critical unique indexes before traffic.
export async function initializeAuthStorage(): Promise<void> {
  const db = mongoose.connection.db;
  if (!db) throw new Error("MongoDB is not connected.");
  const hello = await db.admin().command({ hello: 1 });
  if (!hello.setName && hello.msg !== "isdbgrid") {
    throw new Error("Registration requires MongoDB replica-set transactions.");
  }

  // createIndexes adds missing indexes; it never drops existing indexes.
  for (const model of [
    AuthUserModel,
    CredentialModel,
    OtpChallengeModel,
    PasswordHistoryModel,
    SecurityEventModel,
    AbuseBucketModel,
    SessionModel,
    RefreshTokenModel,
  ]) {
    await model.createCollection();
    await model.createIndexes();
  }
}
