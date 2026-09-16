import { Schema, model, type Types } from "mongoose";

// Payloads are authenticated ciphertext; never persist a plaintext OTP or recipient.
export interface EmailOutbox {
  userId: Types.ObjectId;
  challengeId?: Types.ObjectId;
  kind: "VERIFY" | "RESEND" | "RESET" | "PASSWORD_CHANGED";
  payload?: string;
  expiresAt: Date;
  nextAttemptAt: Date;
  attempts: number;
  leaseId?: string;
  leaseUntil?: Date;
  status: "PENDING" | "SENT" | "EXPIRED";
  requestId: string;
  createdAt: Date;
  completedAt?: Date;
}
const schema = new Schema<EmailOutbox>({
  userId: { type: Schema.Types.ObjectId, required: true },
  challengeId: Schema.Types.ObjectId,
  kind: { type: String, enum: ["VERIFY", "RESEND", "RESET", "PASSWORD_CHANGED"], required: true },
  payload: { type: String, select: false },
  expiresAt: { type: Date, required: true },
  nextAttemptAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  leaseId: String, leaseUntil: Date,
  status: { type: String, enum: ["PENDING", "SENT", "EXPIRED"], default: "PENDING" },
  requestId: { type: String, default: "" },
  completedAt: Date,
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });
schema.index({ status: 1, nextAttemptAt: 1, leaseUntil: 1 });
schema.index({ status: 1, createdAt: 1 });
// Completed ciphertext is removed immediately; metadata is retained for seven days.
schema.index({ completedAt: 1 }, { expireAfterSeconds: 7 * 86400 });
export const EmailOutboxModel = model<EmailOutbox>("EmailOutbox", schema);
