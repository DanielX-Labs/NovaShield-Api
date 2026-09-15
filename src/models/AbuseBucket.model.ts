import mongoose, { Schema } from "mongoose";

// Fixed-window counters are shared across API processes; identifiers are HMACs.
interface AbuseBucket {
  _id: string;
  count: number;
  expiresAt: Date;
}

const abuseBucketSchema = new Schema<AbuseBucket>({
  _id: { type: String, required: true },
  count: { type: Number, required: true },
  expiresAt: { type: Date, required: true },
}, { versionKey: false });

// TTL only removes obsolete windows. Enforcement does not depend on deletion.
abuseBucketSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const AbuseBucketModel =
  mongoose.model<AbuseBucket>("AbuseBucket", abuseBucketSchema);
