import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    environmentOptions: {
      jsdom: {
        url: "https://app.example.test/",
      },
    },
    coverage: {
      reporter: ["text", "json", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.{test,spec}.{ts,tsx}"],
      thresholds: {
        statements: 73,
        branches: 64,
        functions: 72,
        lines: 75,
      },
    },
  },
});
