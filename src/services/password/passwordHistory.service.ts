import type { Types, ClientSession } from "mongoose";
import { env } from "../../config/env.js";
import { PasswordHistoryModel } from "../../models/PasswordHistory.model.js";
import { verifyPassword } from "./passwordHash.service.js";

export async function isPasswordReused(
  userId: Types.ObjectId,
  candidatePassword: string,
): Promise<boolean> {
  // Select hidden hashes explicitly and bound the number of Argon2 operations.
  const history = await PasswordHistoryModel.find({ userId })
    .sort({ createdAt: -1, _id: -1 })
    .limit(env.PASSWORD_HISTORY_LIMIT)
    .select("+passwordHash")
    .lean();

  // Verify sequentially to avoid multiplying peak Argon2 memory consumption.
  for (const previous of history) {
    if (await verifyPassword(previous.passwordHash, candidatePassword)) {
      return true;
    }
  }
  return false;
}

export async function addPasswordToHistory(
  userId: Types.ObjectId,
  passwordHash: string,
  transaction?: ClientSession,
): Promise<void> {
  // Join the credential transaction and remove legacy registration duplicates.
  if (transaction) {
    await PasswordHistoryModel.deleteMany(
      { userId, passwordHash }, { session: transaction },
    );
    await PasswordHistoryModel.create([{ userId, passwordHash }], {
      session: transaction,
    });
  } else {
    await PasswordHistoryModel.create({ userId, passwordHash });
  }

  // ObjectId breaks timestamp ties so retention ordering is deterministic.
  const query = PasswordHistoryModel.find({ userId })
    .sort({ createdAt: -1, _id: -1 })
    .skip(env.PASSWORD_HISTORY_LIMIT)
    .select("_id");
  if (transaction) query.session(transaction);
  const oldEntries = await query.lean();

  if (oldEntries.length === 0) return;

  await PasswordHistoryModel.deleteMany({
    userId,
    _id: { $in: oldEntries.map((entry) => entry._id) },
  }, transaction ? { session: transaction } : undefined);
}
