import mongoose, { type HydratedDocument, type Model, Schema, type Types } from "mongoose";

export type SecurityEventType =
  | "AUTH_REGISTERED"
  | "AUTH_EMAIL_OTP_SENT"
  | "AUTH_EMAIL_OTP_RESENT"
  | "AUTH_EMAIL_OTP_FAILURE"
  | "AUTH_EMAIL_DELIVERY_FAILURE"
  | "AUTH_EMAIL_VERIFIED"
  | "AUTH_LOGIN_SUCCESS"
  | "AUTH_LOGIN_FAILURE"
  | "AUTH_RATE_LIMITED"
  | "AUTH_PASSWORD_CHANGED"
  | "AUTH_PASSWORD_RESET_REQUESTED"
  | "AUTH_PASSWORD_RESET_COMPLETED"
  | "AUTH_PASSWORD_RESET_OTP_FAILURE"
  | "AUTH_SECURITY_NOTIFICATION_FAILURE"
  | "AUTH_REFRESH_ROTATED"
  | "AUTH_REFRESH_REUSED"
  | "AUTH_SESSION_REVOKED"
  | "AUTH_SUSPICIOUS_LOGIN";
export type SecurityEventSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export interface SecurityEvent {
  eventType: SecurityEventType;
  severity: SecurityEventSeverity;
  userId?: Types.ObjectId;
  sessionId?: string;
  requestId?: string;
  ipHash?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
}

export type SecurityEventDocument = HydratedDocument<SecurityEvent>;

const securityEventSchema = new Schema<SecurityEvent>(
  {
    eventType: { type: String, required: true, index: true },
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: "AuthUser", index: true },
    sessionId: { type: String, index: true },
    requestId: { type: String, index: true },
    ipHash: { type: String, select: false },
    userAgent: { type: String, maxlength: 512 },
    // Only store explicitly selected, non-secret metadata; never copy request bodies.
    metadata: { type: Schema.Types.Mixed, default: {} },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  },
);

securityEventSchema.index({ eventType: 1, createdAt: -1 });
securityEventSchema.index({ userId: 1, createdAt: -1 });
securityEventSchema.index({ severity: 1, createdAt: -1 });
// Retention filters by time alone, independently of event category or identity.
securityEventSchema.index({ createdAt: 1 });

export const SecurityEventModel: Model<SecurityEvent> = mongoose.model<SecurityEvent>(
  "SecurityEvent",
  securityEventSchema,
);
