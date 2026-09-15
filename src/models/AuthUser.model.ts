import mongoose, { type HydratedDocument, type Model, Schema } from "mongoose";

export type AuthUserStatus = "PENDING_VERIFICATION" | "ACTIVE" | "SUSPENDED" | "DISABLED";
export interface AuthUser {
  email: string;
  emailNormalized: string;
  isEmailVerified: boolean;
  status: AuthUserStatus;
  failedLoginCount: number;
  lastFailedLoginAt?: Date;
  lastSuccessfulLoginAt?: Date;
  passwordChangedAt?: Date;
  // Shared cooldown gate; transactions serialize resend and verification here.
  verificationOtpIssuedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type AuthUserDocument = HydratedDocument<AuthUser>;

const authUserSchema = new Schema<AuthUser>(
  {
    email: { type: String, required: true, trim: true },
    emailNormalized: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
    isEmailVerified: { type: Boolean, default: false, index: true },
    status: { type: String, enum: ["PENDING_VERIFICATION", "ACTIVE", "SUSPENDED", "DISABLED"], default: "PENDING_VERIFICATION", index: true },
    failedLoginCount: { type: Number, default: 0, min: 0, select: false },
    lastFailedLoginAt: { type: Date, select: false },
    lastSuccessfulLoginAt: { type: Date },
    passwordChangedAt: { type: Date },
    verificationOtpIssuedAt: { type: Date, select: false },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

authUserSchema.index({ status: 1, createdAt: -1 });

export const AuthUserModel: Model<AuthUser> = mongoose.model<AuthUser>(
  "AuthUser",
  authUserSchema,
);
