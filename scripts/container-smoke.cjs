// Run only against disposable Docker resources with generated synthetic secrets.
// This checks the built image without depending on SMTP, HIBP or production data.
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { randomBytes, randomUUID } = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const assert = require("node:assert/strict");
const argon2 = require("argon2");
const { mongo: { MongoClient, ObjectId } } = require("mongoose");
const execute = promisify(execFile);
const suffix = randomUUID().slice(0, 8);
const network = `novashield-smoke-${suffix}`;
const database = `${network}-mongo`;
const api = `${network}-api`;
const origin = "https://smoke-client.example.test";
let directory;
let client;

async function docker(...args) {
  return (await execute("docker", args, { timeout: 120_000, maxBuffer: 1024 * 1024 })).stdout.trim();
}
async function port(name, internal) {
  const state = JSON.parse(await docker("inspect", name))[0];
  return state.NetworkSettings.Ports[`${internal}/tcp`][0].HostPort;
}
async function until(check, message) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try { if (await check()) return; } catch { /* wait for container startup */ }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error(message);
}

async function main() {
  const secret = () => randomBytes(48).toString("hex");
  const pepper = secret();
  const password = `Smoke!${secret()}`;
  await fs.mkdir("tmp", { recursive: true });
  directory = await fs.mkdtemp(path.resolve("tmp", "container-smoke-"));
  const settings = {
    NODE_ENV: "production", PORT: "4001", EXPENSEHUB_ORIGIN: origin,
    MONGODB_URI: "mongodb://mongo:27017/novashield_smoke?replicaSet=rs0",
    JWT_ACCESS_SECRET: secret(), AUTH_PEPPER: pepper, IP_HASH_SECRET: secret(),
    OUTBOX_ENCRYPTION_KEY: randomBytes(32).toString("hex"), OUTBOX_WORKER_ENABLED: "true",
    COOKIE_SECURE: "true", COOKIE_SAME_SITE: "lax", PASSWORD_MIN_LENGTH: "15",
    BREACHED_PASSWORD_CHECK_ENABLED: "true", BREACHED_PASSWORD_FAIL_MODE: "closed",
    EMAIL_PROVIDER: "brevo", BREVO_SENDER_EMAIL: "sender@example.test",
    BREVO_SENDER_NAME: "Smoke test", SUPPORT_EMAIL: "support@example.test",
    BREVO_SMTP_HOST: "127.0.0.1", BREVO_SMTP_PORT: "465",
    BREVO_SMTP_LOGIN: "smoke", BREVO_SMTP_KEY: secret(),
  };
  const envFile = path.join(directory, "runtime.env");
  await fs.writeFile(envFile, Object.entries(settings).map(([key, value]) => `${key}=${value}`).join("\n"), { mode: 0o600 });
  await docker("network", "create", network);
  await docker("run", "-d", "--name", database, "--network", network,
    "--network-alias", "mongo", "-p", "127.0.0.1::27017", "mongo:8.0",
    "--replSet", "rs0", "--bind_ip_all", "--wiredTigerCacheSizeGB", "0.25");
  await until(async () => {
    await docker("exec", database, "mongosh", "--quiet", "--eval", "db.adminCommand({ping:1})");
    return true;
  }, "MongoDB did not start");
  await docker("exec", database, "mongosh", "--quiet", "--eval",
    "rs.initiate({_id:'rs0',members:[{_id:0,host:'mongo:27017'}]})");
  client = new MongoClient(`mongodb://127.0.0.1:${await port(database, 27017)}/?directConnection=true`, {
    serverSelectionTimeoutMS: 3000,
  });
  await client.connect();
  await until(async () => (await client.db("admin").command({ hello: 1 })).isWritablePrimary,
    "Replica set did not elect a primary");
  const userId = new ObjectId();
  const db = client.db("novashield_smoke");
  await db.collection("authusers").insertOne({ _id: userId, email: "smoke@example.test",
    emailNormalized: "smoke@example.test", status: "ACTIVE", isEmailVerified: true,
    failedLoginCount: 0, sessionAdmissionVersion: 0, createdAt: new Date(), updatedAt: new Date() });
  const hash = await argon2.hash(password + pepper, {
    type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1,
  });
  await db.collection("credentials").insertOne({ userId, passwordHash: `ns1:legacy:${hash}`,
    passwordVersion: 1, algorithm: "argon2id", lastChangedAt: new Date() });

  // Exercise the same restrictions recommended for deployment.
  await docker("run", "-d", "--name", api, "--network", network,
    "-p", "127.0.0.1::4001", "--env-file", envFile,
    "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--memory", "512m", "--pids-limit", "128",
    "novashield:ci");
  let base = `http://127.0.0.1:${await port(api, 4001)}/api/v1`;
  const get = endpoint => fetch(base + endpoint, { signal: AbortSignal.timeout(5000) });
  await until(async () => (await get("/ready")).status === 200, "API did not become ready");
  const state = JSON.parse(await docker("inspect", api))[0];
  assert.equal(state.Config.User, "node");
  assert.equal(state.HostConfig.ReadonlyRootfs, true);
  const post = (endpoint, body, cookie, requestOrigin = origin) => fetch(base + endpoint, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: requestOrigin,
      ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
  });
  const loggedIn = await post("/auth/login", { email: "smoke@example.test", password });
  assert.equal(loggedIn.status, 200);
  assert.equal(loggedIn.headers.get("access-control-allow-origin"), origin);
  const loginBody = await loggedIn.json();
  assert.equal(loginBody.data.refreshToken, undefined);
  const setCookie = loggedIn.headers.getSetCookie()[0];
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /Secure/i);
  assert.match(setCookie, /SameSite=Lax/i);
  const cookie = setCookie.split(";")[0];
  assert.equal((await post("/auth/refresh", {}, cookie, "https://attacker.example.test")).status, 403);
  const rotated = await post("/auth/refresh", {}, cookie);
  assert.equal(rotated.status, 200);
  assert.equal((await post("/auth/refresh", {}, cookie)).status, 401);
  const access = (await rotated.json()).data.accessToken;
  assert.equal((await fetch(base + "/auth/sessions", {
    headers: { Authorization: `Bearer ${access}` }, signal: AbortSignal.timeout(5000),
  })).status, 401);
  // A clean shutdown/restart must preserve database state and readiness behavior.
  await docker("stop", "--time", "50", api);
  assert.equal(JSON.parse(await docker("inspect", api))[0].State.ExitCode, 0);
  await docker("start", api);
  base = `http://127.0.0.1:${await port(api, 4001)}/api/v1`;
  await until(async () => (await get("/ready")).status === 200, "API restart failed");
  await client.close();
  client = undefined;
  await docker("stop", database);
  await until(async () => (await get("/ready")).status === 503, "Readiness did not fail on database loss");
  console.log("Container smoke passed: non-root, read-only, cookies, origin, replay, restart and readiness.");
}

main().catch(error => {
  console.error("Container smoke failed:", error.message);
  process.exitCode = 1;
}).finally(async () => {
  if (client) await client.close().catch(() => {});
  // Names are unique to this invocation; cleanup never targets application resources.
  for (const name of [api, database]) await docker("rm", "-f", name).catch(() => {});
  await docker("network", "rm", network).catch(() => {});
  if (directory) {
    await fs.unlink(path.join(directory, "runtime.env"));
    await fs.rmdir(directory);
  }
});
