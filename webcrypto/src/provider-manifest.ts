export const secureTransferWebcryptoProviderManifest = Object.freeze({
  assurance: "experimental" as const,
  costModel: "free" as const,
  description:
    "Browser-native AES-256-GCM authenticated records with a fresh content key and nonce base per transfer.",
  id: "absolutejs.secure-transfer.webcrypto",
  packageName: "@absolutejs/secure-transfer-webcrypto" as const,
  protocol: "ABS-A256GCM-RECORDS-1",
  runtimes: ["browser", "bun", "node"] as const,
  version: "0.0.1",
});
