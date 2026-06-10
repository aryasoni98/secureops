import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Relative base so the bundle works at https://<user>.github.io/secureops/.
export default defineConfig({
  base: "./",
  plugins: [react()],
});
