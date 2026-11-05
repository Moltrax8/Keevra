import { defineConfig } from "vitest/config";

// Unit tests are colocated `*.test.ts` beside the domain modules they cover.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["node_modules/**", "dist/**", "src-tauri/**"],
  },
});
