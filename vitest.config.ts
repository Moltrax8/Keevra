import { defineConfig } from "vitest/config";

// Unit tests are colocated `*.test.ts(x)` beside the domain modules and hooks
// they cover. Hook tests opt into jsdom with a per-file environment comment.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    exclude: ["node_modules/**", "dist/**", "src-tauri/**"],
  },
});
