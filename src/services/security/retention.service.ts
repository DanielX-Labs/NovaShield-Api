import mongoose from "mongoose";
import { env } from "../../config/env.js";
import { SessionModel } from "../../models/Session.model.js";
import { RefreshTokenModel } from "../../models/RefreshToken.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { SecurityEventModel } from "../../models/SecurityEvent.model.js";

// Delete bounded batches. Refresh replay evidence survives absolute family expiry plus grace.
export async function runRetention(): Promise<void> {
  const expiredBefore = new Date(Date.now() - env.AUTH_RECORD_RETENTION_DAYS * 86400_000);
  for (const model of [RefreshTokenModel, SessionModel, OtpChallengeModel]) {
    const collection = mongoose.connection.db!.collection(model.collection.name);
    const ids = await collection.find({ expiresAt: { $lt: expiredBefore } }).limit(500).project({ _id: 1 }).toArray();
    if (ids.length) await collection.deleteMany({ _id: { $in: ids.map(row => row._id) }, expiresAt: { $lt: expiredBefore } });
  }
  const auditBefore = new Date(Date.now() - env.SECURITY_EVENT_RETENTION_DAYS * 86400_000);
  const ids = await SecurityEventModel.find({ createdAt: { $lt: auditBefore } })
    .sort({ createdAt: 1 }).hint({ createdAt: 1 }).limit(500).select("_id").lean();
  if (ids.length) await SecurityEventModel.deleteMany({ _id: { $in: ids.map(row => row._id) } });
}
