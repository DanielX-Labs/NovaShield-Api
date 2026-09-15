import mongoose, {
  type HydratedDocument,
  type Model,
  Schema,
  type Types,
} from "mongoose";

// History stores encoded hashes only, never the original password.
export interface PasswordHistory {
  userId: Types.ObjectId;
  passwordHash: string;
  createdAt: Date;
}

export type PasswordHistoryDocument =
  HydratedDocument<PasswordHistory>;

const passwordHistorySchema = new Schema<PasswordHistory>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "AuthUser",
      required: true,
      index: true,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },
  },
  {
    // History records have a creation time, with no update timestamp.
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  },
);

// Newest hashes are read first during reuse checks.
passwordHistorySchema.index({ userId: 1, createdAt: -1 });

export const PasswordHistoryModel: Model<PasswordHistory> =
  mongoose.model<PasswordHistory>(
    "PasswordHistory",
    passwordHistorySchema,
  );
