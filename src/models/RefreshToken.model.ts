import mongoose, { type HydratedDocument, type Model, Schema, type Types } from "mongoose";

export interface RefreshToken {
  userId: Types.ObjectId;
  sessionId: Types.ObjectId;
  familyId: string;
  tokenHash: string;
  expiresAt: Date;
  usedAt?: Date;
  revokedAt?: Date;
  replacedByTokenId?: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

export type RefreshTokenDocument = HydratedDocument<RefreshToken>;

const refreshTokenSchema = new Schema<RefreshToken>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "AuthUser", required: true, index: true },
    sessionId: { type: Schema.Types.ObjectId, ref: "Session", required: true, index: true },
    familyId: { type: String, required: true, index: true },
    tokenHash: { type: String, required: true, unique: true, select: false },
    expiresAt: { type: Date, required: true, index: true },
    usedAt: { type: Date, select: false },
    revokedAt: { type: Date, select: false },
    replacedByTokenId: { type: Schema.Types.ObjectId, ref: "RefreshToken", select: false },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

refreshTokenSchema.index({ familyId: 1, createdAt: 1 });
refreshTokenSchema.index({ userId: 1, sessionId: 1 });

export const RefreshTokenModel: Model<RefreshToken> = mongoose.model<RefreshToken>(
  "RefreshToken",
  refreshTokenSchema,
);

