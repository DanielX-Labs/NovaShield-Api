import type { ClientSession, Types } from "mongoose";
import { CredentialModel } from "../../models/Credential.model.js";

// Password hashes are explicitly selected only for authentication internals.
export function getCredentialForAuthentication(
  userId: Types.ObjectId,
  session?: ClientSession,
) {
  const query = CredentialModel.findOne({ userId }).select("+passwordHash");
  return session ? query.session(session) : query;
}
