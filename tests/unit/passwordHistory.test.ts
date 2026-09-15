import { Types } from "mongoose";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock persistence so these tests cannot connect to a real database.
const mocks = vi.hoisted(() => ({
  find: vi.fn(),
  create: vi.fn(),
  deleteMany: vi.fn(),
  verify: vi.fn(),
}));
vi.mock("../../src/config/env.js", () => ({
  env: { PASSWORD_HISTORY_LIMIT: 5 },
}));
vi.mock("../../src/models/PasswordHistory.model.js", () => ({
  PasswordHistoryModel: mocks,
}));
vi.mock("../../src/services/password/passwordHash.service.js", () => ({
  verifyPassword: mocks.verify,
}));
import {
  addPasswordToHistory,
  isPasswordReused,
} from "../../src/services/password/passwordHistory.service.js";

const userId = new Types.ObjectId();

function queryReturning(entries: unknown[]) {
  const query = {
    sort: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    lean: vi.fn().mockResolvedValue(entries),
  };
  mocks.find.mockReturnValue(query);
  return query;
}

beforeEach(() => vi.resetAllMocks());

describe("Password history", () => {
  it("detects reuse and stops after a matching hash", async () => {
    const query = queryReturning([
      { passwordHash: "newer" },
      { passwordHash: "older" },
      { passwordHash: "oldest" },
    ]);
    mocks.verify.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    await expect(isPasswordReused(userId, "candidate")).resolves.toBe(true);
    expect(mocks.find).toHaveBeenCalledWith({ userId });
    expect(query.limit).toHaveBeenCalledWith(5);
    expect(query.select).toHaveBeenCalledWith("+passwordHash");
    expect(mocks.verify).toHaveBeenCalledTimes(2);
  });

  it("accepts a password absent from history", async () => {
    queryReturning([{ passwordHash: "previous" }]);
    mocks.verify.mockResolvedValue(false);
    await expect(isPasswordReused(userId, "candidate")).resolves.toBe(false);
  });

  it("keeps the newest entries and deletes only this user's overflow", async () => {
    const oldId = new Types.ObjectId();
    const query = queryReturning([{ _id: oldId }]);
    await addPasswordToHistory(userId, "encoded-hash");
    expect(mocks.create).toHaveBeenCalledWith({
      userId, passwordHash: "encoded-hash",
    });
    expect(query.skip).toHaveBeenCalledWith(5);
    expect(query.sort).toHaveBeenCalledWith({ createdAt: -1, _id: -1 });
    expect(mocks.deleteMany).toHaveBeenCalledWith({
      userId, _id: { $in: [oldId] },
    });
  });

  it("does not delete entries when history is within the limit", async () => {
    queryReturning([]);
    await addPasswordToHistory(userId, "encoded-hash");
    expect(mocks.deleteMany).not.toHaveBeenCalled();
  });
});
