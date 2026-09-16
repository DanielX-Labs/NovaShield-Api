import { defineConfig } from "vitest/config";

// Bound parallel workers because each database suite owns a replica set and Argon2 work.
export default defineConfig({ test: { maxWorkers: 4 } });
