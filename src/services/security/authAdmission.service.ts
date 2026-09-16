import mongoose, { type ClientSession } from "mongoose";
import { AbuseBucketModel } from "../../models/AbuseBucket.model.js";
import { env } from "../../config/env.js";
import { AppError } from "../../utils/AppError.js";
import { hashAuthIdentifier } from "./identifierHash.service.js";

export interface Admission { ids: string[] }

export async function admitLogin(email: string, ipHash: string): Promise<Admission> {
  const windowMs = env.AUTH_FAILURE_WINDOW_MINUTES * 60_000;
  const window = Math.floor(Date.now() / windowMs);
  // Pair limits stop one source targeting an account without globally locking it.
  const buckets = [
    { id: `admit-ip:${ipHash}:${window}`, limit: env.AUTH_IP_FAILURE_LIMIT },
    { id: `admit-pair:${ipHash}:${hashAuthIdentifier(email)}:${window}`,
      limit: env.AUTH_ACCOUNT_FAILURE_LIMIT },
  ];
  for (let retry = 0; retry < 3; retry += 1) {
    try {
      return await mongoose.connection.transaction(async (session) => {
        for (const bucket of buckets) {
          const result = await AbuseBucketModel.findOneAndUpdate({ _id: bucket.id }, {
            $inc: { count: 1 },
            $setOnInsert: { expiresAt: new Date((window + 2) * windowMs) },
          }, { upsert: true, returnDocument: "after", session });
          if (result.count > bucket.limit) {
            // Throwing rolls back both reservations, including on partial admission.
            throw new AppError("Too many authentication attempts. Please try again later.",
              429, "AUTH_RATE_LIMITED");
          }
        }
        return { ids: buckets.map((bucket) => bucket.id) };
      });
    } catch (error) {
      // Two first requests can race on the unique bucket key.
      if ((error as { code?: number }).code !== 11000 || retry === 2) throw error;
    }
  }
  throw new AppError("Authentication is temporarily unavailable.", 503, "AUTH_UNAVAILABLE");
}

export async function releaseAdmission(
  admission: Admission,
  session?: ClientSession,
): Promise<void> {
  // Success refunds its exact window; completed failures retain their reservation.
  for (const id of admission.ids) {
    await AbuseBucketModel.updateOne({ _id: id, count: { $gt: 0 } }, {
      $inc: { count: -1 },
    }, session ? { session } : {});
  }
}
