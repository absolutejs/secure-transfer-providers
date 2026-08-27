import { describe, expect, test } from "bun:test";
import type { SecureTransferRecordContext } from "@absolutejs/secure-transfer";
import { createSecureTransferWebcryptoProvider } from "../src";

const context: SecureTransferRecordContext = {
  attachmentId: "attachment-1",
  conversationId: "conversation-1",
  expiresAt: 2_000,
  final: false,
  plaintextBytes: 3,
  recordCount: 2,
  recordIndex: 0,
  senderDeviceId: "alice-phone",
  transferId: "transfer-1",
};

describe("secure transfer WebCrypto provider", () => {
  test("round-trips a record with a non-exportable imported operation key", async () => {
    const provider = createSecureTransferWebcryptoProvider();
    const capability = await provider.createCapability();
    const ciphertext = await provider.sealRecord({
      capability,
      context,
      plaintext: Uint8Array.of(1, 2, 3),
    });
    expect(ciphertext).not.toEqual(Uint8Array.of(1, 2, 3));
    expect(
      await provider.openRecord({ capability, ciphertext, context }),
    ).toEqual(Uint8Array.of(1, 2, 3));
  });

  for (const field of [
    "attachmentId",
    "conversationId",
    "expiresAt",
    "final",
    "plaintextBytes",
    "recordCount",
    "recordIndex",
    "senderDeviceId",
    "transferId",
  ] as const)
    test(`rejects authenticated ${field} substitution`, async () => {
      const provider = createSecureTransferWebcryptoProvider();
      const capability = await provider.createCapability();
      const ciphertext = await provider.sealRecord({
        capability,
        context,
        plaintext: Uint8Array.of(1, 2, 3),
      });
      const changed = {
        ...context,
        [field]:
          field === "final"
            ? true
            : typeof context[field] === "number"
              ? Number(context[field]) + 1
              : `${context[field]}-changed`,
      } as SecureTransferRecordContext;
      await expect(
        provider.openRecord({ capability, ciphertext, context: changed }),
      ).rejects.toThrow();
    });

  test("rejects ciphertext tampering and capability substitution", async () => {
    const provider = createSecureTransferWebcryptoProvider();
    const capability = await provider.createCapability();
    const ciphertext = await provider.sealRecord({
      capability,
      context,
      plaintext: Uint8Array.of(1, 2, 3),
    });
    const original = ciphertext.slice();
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    await expect(
      provider.openRecord({ capability, ciphertext, context }),
    ).rejects.toThrow("authentication failed");
    const another = await provider.createCapability();
    await expect(
      provider.openRecord({
        capability: another,
        ciphertext: original,
        context,
      }),
    ).rejects.toThrow();
  });

  test("uses a fresh capability for each transfer", async () => {
    const provider = createSecureTransferWebcryptoProvider();
    const first = await provider.createCapability();
    const second = await provider.createCapability();
    expect(first.bytes).not.toEqual(second.bytes);
  });
});
