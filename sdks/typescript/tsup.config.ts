import { defineConfig } from "tsup";

/**
 * Build du SDK Thot Secure (ex-Thot Secure).
 *
 * * ESM (`dist/index.js`) + CJS (`dist/index.cjs`) + déclarations (`dist/index.d.ts`).
 * * `platform: "neutral"` : aucune API Node n'est injectée, le SDK reste utilisable dans un
 *   navigateur (fetch, WebSocket, Web Crypto) comme dans Node ≥ 20.
 * * **Zéro dépendance runtime** : rien n'est marqué `external`, tout le code du SDK est bundlé.
 */
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  target: "es2022",
  platform: "neutral",
  dts: true,
  sourcemap: true,
  clean: true,
  minify: false,
  splitting: false,
  treeshake: true,
});
