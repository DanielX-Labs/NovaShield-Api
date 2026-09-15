// Run after npm run build. This diagnostic uses a public, known-breached value.
// It makes one real HIBP request and never reads a customer's password.
const {
  checkBreachedPassword,
} = require("../dist/services/password/breachedPassword.service.js");

checkBreachedPassword("password")
  .then((result) => {
    if (!result.checked || !result.breached) {
      throw new Error("Expected the known compromised test value to be detected.");
    }
    console.log("Live HIBP adapter check passed.");
  })
  .catch(() => {
    // Do not print upstream request details or environment values.
    console.error("Live HIBP adapter check failed.");
    process.exitCode = 1;
  });
