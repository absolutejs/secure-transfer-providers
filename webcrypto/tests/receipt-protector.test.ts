import { describe, expect, test } from "bun:test";
import { createSecureTransferWebcryptoReceiptProtector } from "../src";

describe("WebCrypto protected upload receipts", () => {
  test("round-trips with per-receipt key derivation and fresh nonces", async () => {
    const root = crypto.getRandomValues(new Uint8Array(32));
    const protector = await createSecureTransferWebcryptoReceiptProtector({
      key: root,
    });
    root.fill(0);
    const plaintext = new TextEncoder().encode("bearer capability receipt");
    const first = await protector.protect({
      plaintext,
      receiptId: "receipt-a",
    });
    const second = await protector.protect({
      plaintext,
      receiptId: "receipt-a",
    });
    expect(first).not.toEqual(second);
    expect(new TextDecoder().decode(first)).not.toContain("bearer capability");
    expect(
      await protector.open({ protectedBytes: first, receiptId: "receipt-a" }),
    ).toEqual(plaintext);
  });

  test("rejects tampering, receipt substitution, and root-key substitution", async () => {
    const protector = await createSecureTransferWebcryptoReceiptProtector({
      key: crypto.getRandomValues(new Uint8Array(32)),
    });
    const protectedBytes = await protector.protect({
      plaintext: Uint8Array.of(1, 2, 3),
      receiptId: "receipt-a",
    });
    const tampered = protectedBytes.slice();
    tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 1;
    await expect(
      protector.open({ protectedBytes: tampered, receiptId: "receipt-a" }),
    ).rejects.toThrow("authentication failed");
    await expect(
      protector.open({ protectedBytes, receiptId: "receipt-b" }),
    ).rejects.toThrow("authentication failed");
    const another = await createSecureTransferWebcryptoReceiptProtector({
      key: crypto.getRandomValues(new Uint8Array(32)),
    });
    await expect(
      another.open({ protectedBytes, receiptId: "receipt-a" }),
    ).rejects.toThrow("authentication failed");
  });

  test("rejects weak root keys and incompatible CryptoKeys", async () => {
    await expect(
      createSecureTransferWebcryptoReceiptProtector({
        key: new Uint8Array(16),
      }),
    ).rejects.toThrow("32 bytes");
    const incompatible = await crypto.subtle.importKey(
      "raw",
      crypto.getRandomValues(new Uint8Array(32)),
      "AES-GCM",
      false,
      ["encrypt"],
    );
    await expect(
      createSecureTransferWebcryptoReceiptProtector({ key: incompatible }),
    ).rejects.toThrow("HKDF");
  });
});
