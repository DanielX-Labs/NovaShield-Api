// Explicit manual check only. Requires a running local API and an authorized inbox.
// A random test password stays in memory; neither it nor the OTP is saved to disk.
const { randomBytes } = require("node:crypto");
const { mkdirSync, readFileSync, writeFileSync } = require("node:fs");
const mongoose = require("mongoose");
const { env } = require("../dist/config/env.js");
const { assessPassword } = require("../dist/services/password/passwordPolicy.service.js");
const { verifyPassword } = require("../dist/services/password/passwordHash.service.js");
const { verifyOtpHash } = require("../dist/services/otp/otp.service.js");

const statePath = "tmp/live-registration-check.json";
const base = "http://127.0.0.1:" + env.PORT + "/api/v1";

async function post(path, body) {
  const response = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const result = await response.json();
  console.log(path + " HTTP " + response.status);
  if (!response.ok) {
    throw new Error(result.error?.code ?? "REQUEST_FAILED");
  }
  return result;
}

async function inspect(state, password, otp) {
  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  try {
    const db = mongoose.connection.db;
    const user = await db.collection("authusers").findOne({
      emailNormalized: state.email,
    });
    if (!user) throw new Error("TEST_USER_MISSING");
    const credential = await db.collection("credentials").findOne({ userId: user._id });
    const challenge = await db.collection("otpchallenges").findOne({
      _id: new mongoose.Types.ObjectId(state.challengeId),
      userId: user._id,
    });
    const events = await db.collection("securityevents").find({
      userId: user._id,
    }).toArray();
    if (!credential || !challenge) throw new Error("EXPECTED_RECORD_MISSING");
    if (!credential.passwordHash.includes("$argon2id$")
      || !/^[a-f0-9]{64}$/.test(challenge.otpHash)) {
      throw new Error("UNEXPECTED_HASH_FORMAT");
    }
    if (password && !await verifyPassword(credential.passwordHash, password)) {
      throw new Error("PASSWORD_HASH_MISMATCH");
    }
    if (otp && !verifyOtpHash(otp, state.challengeId, challenge.otpHash)) {
      throw new Error("OTP_HASH_MISMATCH");
    }

    // Assert only; never print full MongoDB documents or hash values.
    const records = JSON.stringify([user, credential, challenge, ...events]);
    if ((password && records.includes(password))
      || (otp && records.includes('"' + otp + '"'))
      || records.includes('"password":') || records.includes('"otp":')) {
      throw new Error("PLAINTEXT_SECRET_FOUND");
    }
    console.log("AuthUser status:", user.status);
    console.log("Email verified:", user.isEmailVerified);
    console.log("Credential: Argon2id; OTP: challenge-bound HMAC");
    console.log("Security events:", events.map((event) => event.eventType).join(", "));
    console.log("Plaintext secret checks passed.");
    if (otp && (user.status !== "ACTIVE" || !user.isEmailVerified
      || !challenge.consumedAt
      || !events.some((event) => event.eventType === "AUTH_EMAIL_VERIFIED"))) {
      throw new Error("ACTIVATION_NOT_COMPLETE");
    }
  } finally {
    await mongoose.disconnect();
  }
}

async function main() {
  const mode = process.argv[2];
  if (mode === "register") {
    const email = process.argv[3]?.trim().toLowerCase();
    if (!email) throw new Error("An authorized test inbox is required.");
    let password;
    do {
      password = randomBytes(32).toString("base64url");
    } while (!assessPassword(password, { email }).valid);

    const result = await post("/auth/register", { email, password });
    const state = { email, challengeId: result.data.challengeId };
    mkdirSync("tmp", { recursive: true });
    writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
    await inspect(state, password);
  } else if (mode === "resend") {
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    const result = await post("/email/resend", { email: state.email });
    state.challengeId = result.data.challengeId;
    writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
    await inspect(state);
  } else if (mode === "verify") {
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    const otp = process.env.NOVASHIELD_TEST_OTP;
    if (!/^\d{6}$/.test(otp ?? "")) throw new Error("A six-digit OTP is required.");
    await post("/email/verify", { challengeId: state.challengeId, otp });
    await inspect(state, undefined, otp);
  } else {
    throw new Error("Use register <authorized-email>, resend, or verify.");
  }
}

main().catch((error) => {
  // Messages above are fixed codes and never include request bodies or secrets.
  console.error(error instanceof Error ? error.message : "Live check failed.");
  process.exitCode = 1;
});
