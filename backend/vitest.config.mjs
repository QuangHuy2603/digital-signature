import "dotenv/config";
import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["tests/**/*.test.js"],
        pool: "threads",
        fileParallelism: false,
        maxWorkers: 1,
        testTimeout: 120000,
        hookTimeout: 120000,
        teardownTimeout: 30000,
    },
});
