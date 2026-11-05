import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Keep Rust errors visible during Tauri development.
  clearScreen: false,
  server: {
    // Must match the devUrl in src-tauri/tauri.conf.json.
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
