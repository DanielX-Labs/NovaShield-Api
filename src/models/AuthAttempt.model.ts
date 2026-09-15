import { Schema, model, type HydratedDocument, type Model, type Types } from "mongoose";

export type AuthAttemptOutcome = "SUCCESS" | "FAILURE" | "BLOCKED";
export type AuthAttemptReason =
  | "INVALID_CREDENTIALS"
  | "ACCOUNT_NOT_AVAILABLE"
  | "RATE_LIMITED"
  | "SUCCESS";

// Attempt telemetry contains protected identifiers, never submitted credentials.
export interface AuthAttempt {
  emailHash: string;
  ipHash?: string;
  outcome: AuthAttemptOutcome;
  reason: AuthAttemptReason;
  userId?: Types.ObjectId;
  createdAt: Date;
}
export type AuthAttemptDocument = HydratedDocument<AuthAttempt>;

const authAttemptSchema = new Schema<AuthAttempt>({
  emailHash: { type: String, required: true },
  ipHash: { type: String },
  outcome: {
    type: String, enum: ["SUCCESS", "FAILURE", "BLOCKED"], required: true,
  },
  reason: {
    type: String,
    enum: ["INVALID_CREDENTIALS", "ACCOUNT_NOT_AVAILABLE", "RATE_LIMITED", "SUCCESS"],
    required: true,
  },
  userId: { type: Schema.Types.ObjectId, ref: "AuthUser" },
}, {
  timestamps: { createdAt: true, updatedAt: false },
  versionKey: false,
});

// Include outcome in the rolling-query indexes to avoid scanning success records.
authAttemptSchema.index({ emailHash: 1, outcome: 1, createdAt: -1 });
authAttemptSchema.index({ ipHash: 1, outcome: 1, createdAt: -1, emailHash: 1 });
// TTL only removes old telemetry; authorization always supplies an explicit window.
authAttemptSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7 * 24 * 60 * 60 });

export const AuthAttemptModel: Model<AuthAttempt> =
  model<AuthAttempt>("AuthAttempt", authAttemptSchema);
