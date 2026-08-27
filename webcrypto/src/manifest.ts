import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams"],
    intents: [
      "encrypt secure-transfer records with browser WebCrypto",
      "authenticate large object record ordering and metadata",
      "protect resumable upload receipts with per-receipt derived keys",
    ],
    keywords: ["AES-256-GCM", "WebCrypto", "secure transfer", "records"],
    protocols: ["ABS-A256GCM-RECORDS-1", "HKDF-SHA256 + AES-256-GCM"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "WebCrypto AES-256-GCM provider for AbsoluteJS secure-transfer authenticated records.",
    docsUrl:
      "https://github.com/absolutejs/secure-transfer-providers/tree/main/webcrypto",
    name: "@absolutejs/secure-transfer-webcrypto",
    tagline: "Encrypt large-object records with browser-native cryptography.",
  },
  settings: Type.Object({}, { additionalProperties: false }),
  wiring: [],
});
