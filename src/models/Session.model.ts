import mongoose, { type HydratedDocument, type Model, Schema, type Types } from "mongoose";

export interface Session {
  userId: Types.ObjectId;
  sessionId: string;
  // Bind refresh capability to the credential version that created the session.
  passwordVersion: number;
  userAgent?: string;
  ipHash?: string;
  lastSeenAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  revokeReason?: string;
  createdAt: Date;
  updatedAt: Date;
}

export type SessionDocument = HydratedDocument<Session>;

const sessionSchema = new Schema<Session>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "AuthUser", required: true, index: true },
    sessionId: { type: String, required: true, unique: true, index: true, immutable: true },
    passwordVersion: { type: Number, required: true, min: 1, immutable: true },
    userAgent: { type: String, maxlength: 512 },
    ipHash: { type: String, select: false },
    lastSeenAt: { type: Date, required: true, default: Date.now },
    expiresAt: { type: Date, required: true, index: true },
    revokedAt: { type: Date, index: true },
    revokeReason: { type: String, maxlength: 250 },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

sessionSchema.index({ userId: 1, revokedAt: 1 });

export const SessionModel: Model<Session> = mongoose.model<Session>(
  "Session",
  sessionSchema,
);
