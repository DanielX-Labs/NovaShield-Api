import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Lint maintained source, tests and scripts; generated output is never checked in.
export default tseslint.config(
  { ignores: ["node_modules/**", "dist/**", "coverage/**", "tmp/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: Object.fromEntries([
      "console", "process", "Buffer", "URL", "fetch", "AbortController", "AbortSignal",
      "setTimeout", "clearTimeout", "setInterval", "clearInterval", "require", "module",
    ].map(name => [name, "readonly"])) },
    rules: { "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }] },
  },
  { files: ["scripts/**/*.cjs"], rules: { "@typescript-eslint/no-require-imports": "off" } },
  // Mongoose's overloaded methods require flexible signatures in fault-injection mocks.
  { files: ["tests/**/*.ts"], rules: { "@typescript-eslint/no-explicit-any": "off" } },
);
