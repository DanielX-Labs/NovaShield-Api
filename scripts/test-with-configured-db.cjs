// Explicit opt-in runner for environments where downloading mongod is impractical.
// Tests use a generated ns_it_* database and remove only that DB.
const { readFileSync } = require("node:fs");
const { spawn } = require("node:child_process");
const { dirname, join } = require("node:path");
const { parse } = require("dotenv");

const config = parse(readFileSync(".env"));
if (!config.MONGODB_URI) {
  throw new Error("A configured MongoDB replica set is required.");
}

// Pass credentials privately through the child environment, never command arguments.
const child = spawn(
  process.execPath,
  [join(dirname(require.resolve("vitest/package.json")), "vitest.mjs"), "run"],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      NOVASHIELD_TEST_MONGODB_URI: config.MONGODB_URI,
    },
  },
);
child.on("exit", (code) => { process.exitCode = code ?? 1; });
child.on("error", () => {
  console.error("Could not start the test runner.");
  process.exitCode = 1;
});
