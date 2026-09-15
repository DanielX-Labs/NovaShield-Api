import mongoose, { type HydratedDocument, type Model, Schema, type Types } from "mongoose";

export interface Credential {
  userId: Types.ObjectId;
  passwordHash: string;
  passwordVersion: number;
  algorithm: "argon2id";
  lastChangedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type CredentialDocument = HydratedDocument<Credential>;

const credentialSchema = new Schema<Credential>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "AuthUser", required: true, unique: true, index: true, immutable: true },
    passwordHash: { type: String, required: true, select: false },
    passwordVersion: { type: Number, default: 1, min: 1 },
    algorithm: { type: String, enum: ["argon2id"], default: "argon2id", immutable: true },
    lastChangedAt: { type: Date, required: true, default: Date.now },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);



export const CredentialModel: Model<Credential> = mongoose.model<Credential>(
  "Credential",
  credentialSchema,
);

