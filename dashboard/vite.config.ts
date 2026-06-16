import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves the project site under /spring-taint/; the dev server stays at root.
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/spring-taint/" : "/",
  plugins: [react()],
  server: { port: 4321, strictPort: true, host: true },
}));
