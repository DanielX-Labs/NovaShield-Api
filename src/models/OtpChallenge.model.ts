import mongoose, { type HydratedDocument, type Model, Schema, type Types } from "mongoose";

export type OtpPurpose = "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "EMAIL_CHANGE" | "PASSWORD_CHANGE";
export interface OtpChallenge {
  userId: Types.ObjectId;
  purpose: OtpPurpose;
  otpHash: string;
  target: string;
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
  // Reset challenges cannot authorize changes against a newer credential.
  credentialVersion?: number;
  resetProtocolVersion?: number;
  verificationProtocolVersion?: number;
  consumedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type OtpChallengeDocument = HydratedDocument<OtpChallenge>;

const otpChallengeSchema = new Schema<OtpChallenge>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "AuthUser", required: true, index: true },
    purpose: { type: String, enum: ["EMAIL_VERIFICATION", "PASSWORD_RESET", "EMAIL_CHANGE", "PASSWORD_CHANGE"], required: true, index: true },
    otpHash: { type: String, required: true, select: false },
    target: { type: String, required: true, select: false },
    expiresAt: { type: Date, required: true, index: true },
    attempts: { type: Number, default: 0, min: 0, select: false },
    maxAttempts: { type: Number, required: true, min: 1, select: false },
    credentialVersion: { type: Number, min: 1, select: false },
    resetProtocolVersion: { type: Number, enum: [2], select: false },
    verificationProtocolVersion: { type: Number, enum: [2], select: false },
    consumedAt: { type: Date, select: false },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

otpChallengeSchema.index({ userId: 1, purpose: 1, createdAt: -1 });

export const OtpChallengeModel: Model<OtpChallenge> = mongoose.model<OtpChallenge>(
  "OtpChallenge",
  otpChallengeSchema,
);
