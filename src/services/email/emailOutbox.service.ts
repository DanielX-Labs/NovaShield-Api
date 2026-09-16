import { randomUUID } from "node:crypto";
import mongoose, { Types, type ClientSession } from "mongoose";
import { z } from "zod";
import { EmailOutboxModel, type EmailOutbox } from "../../models/EmailOutbox.model.js";
import { OtpChallengeModel } from "../../models/OtpChallenge.model.js";
import { encryptOutbox, decryptOutbox } from "./outboxCrypto.service.js";
import { sendVerificationOtpEmail, sendPasswordResetOtpEmail, sendPasswordChangedEmail } from "./email.service.js";
import { recordSecurityEvent } from "../security/securityEvent.service.js";
import { logger } from "../../config/logger.js";

const payloadSchema = z.object({ email: z.string().email(), otp: z.string().regex(/^\d{6}$/u).optional() }).strict();

export async function enqueueEmail(input: {
  userId: Types.ObjectId; challengeId?: Types.ObjectId;
  kind: EmailOutbox["kind"]; email: string; otp?: string; expiresAt: Date; requestId: string;
}, session: ClientSession): Promise<void> {
  const id = new Types.ObjectId();
  const payload = payloadSchema.parse({ email: input.email, ...(input.otp ? { otp: input.otp } : {}) });
  // Bind ciphertext to its job ID so it cannot be transplanted onto another job.
  await EmailOutboxModel.create([{
    _id: id, userId: input.userId, kind: input.kind,
    ...(input.challengeId ? { challengeId: input.challengeId } : {}),
    payload: encryptOutbox(JSON.stringify(payload), id.toHexString()),
    expiresAt: input.expiresAt, nextAttemptAt: new Date(), requestId: input.requestId,
  }], { session });
}

export async function processOneEmail(): Promise<boolean> {
  const now = new Date();
  const leaseId = randomUUID();
  // Atomic leases coordinate workers. SMTP timeouts must remain shorter than this lease.
  const job = await EmailOutboxModel.findOneAndUpdate({
    status: "PENDING", nextAttemptAt: { $lte: now },
    $or: [{ leaseUntil: { $exists: false } }, { leaseUntil: { $lte: now } }],
  }, { $set: { leaseId, leaseUntil: new Date(now.getTime() + 120_000) }, $inc: { attempts: 1 } }, {
    sort: { nextAttemptAt: 1 }, returnDocument: "after",
  }).select("+payload");
  if (!job) return false;
  const owned = { _id: job._id, leaseId, status: "PENDING" as const };
  // Renew ownership during slow SMTP operations; a crash still releases the job by expiry.
  const heartbeat = setInterval(() => {
    void EmailOutboxModel.updateOne(owned, { $set: { leaseUntil: new Date(Date.now() + 120_000) } })
      .catch(() => undefined);
  }, 30_000);
  heartbeat.unref();
  try {
    const challenge = job.challengeId ? await OtpChallengeModel.findById(job.challengeId)
      .select("+consumedAt +resetProtocolVersion +verificationProtocolVersion") : null;
    if (job.expiresAt <= now
      || (job.kind === "RESET" && challenge?.resetProtocolVersion !== 2)
      || (["VERIFY", "RESEND"].includes(job.kind) && challenge?.verificationProtocolVersion !== 2)
      || (job.challengeId && (!challenge || challenge.consumedAt || challenge.expiresAt <= now))) {
      await EmailOutboxModel.updateOne(owned, {
        $set: { status: "EXPIRED", completedAt: now }, $unset: { payload: 1, leaseUntil: 1, leaseId: 1 },
      });
      return true;
    }
    const payload = payloadSchema.parse(JSON.parse(decryptOutbox(job.payload!, job._id.toHexString())));
    if (job.kind === "PASSWORD_CHANGED") await sendPasswordChangedEmail(payload.email);
    else {
      if (!payload.otp) throw new Error("Missing OTP payload.");
      const expiresAt = challenge?.expiresAt ?? job.expiresAt;
      if (job.kind === "RESET") await sendPasswordResetOtpEmail(
        payload.email, payload.otp, expiresAt, job.challengeId?.toHexString(),
      );
      else await sendVerificationOtpEmail(
        payload.email, payload.otp, expiresAt, job.challengeId?.toHexString(),
      );
    }
    await mongoose.connection.transaction(async (session) => {
      const result = await EmailOutboxModel.updateOne(owned, {
        $set: { status: "SENT", completedAt: new Date() },
        $unset: { payload: 1, leaseUntil: 1, leaseId: 1 },
      }, { session });
      if (result.modifiedCount && (job.kind === "VERIFY" || job.kind === "RESEND")) {
        await recordSecurityEvent(job.kind === "VERIFY" ? "AUTH_EMAIL_OTP_SENT" : "AUTH_EMAIL_OTP_RESENT",
          { requestId: job.requestId, ipHash: "" }, job.userId, session);
      }
    });
  } catch (error) {
    logger.error({ err: error, operation: "outbox.delivery", requestId: job.requestId },
      "Email job will be retried");
    // Do not log SMTP errors or payloads: they can contain recipients and message data.
    await mongoose.connection.transaction(async (session) => {
      const released = await EmailOutboxModel.updateOne(owned, {
        $set: { nextAttemptAt: new Date(Date.now() + Math.min(300_000, 1000 * 2 ** Math.min(job.attempts, 9))) },
        $unset: { leaseUntil: 1, leaseId: 1 },
      }, { session });
      if (released.modifiedCount && job.attempts === 1) await recordSecurityEvent(
        job.kind === "PASSWORD_CHANGED" ? "AUTH_SECURITY_NOTIFICATION_FAILURE" : "AUTH_EMAIL_DELIVERY_FAILURE",
        { requestId: job.requestId, ipHash: "" }, job.userId, session, "LOW",
      );
    });
  } finally { clearInterval(heartbeat); }
  return true;
}
