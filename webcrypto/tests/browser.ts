import { createSecureTransferWebcryptoProvider } from "../src";

const scope = globalThis as typeof globalThis & {
  __absoluteSecureTransferCertification?: Promise<{
    readonly error?: string;
    readonly ok: boolean;
  }>;
};

scope.__absoluteSecureTransferCertification = (async () => {
  try {
    const provider = createSecureTransferWebcryptoProvider();
    const capability = await provider.createCapability();
    const context = {
      attachmentId: "browser-attachment",
      conversationId: "browser-conversation",
      expiresAt: Date.now() + 60_000,
      final: true,
      plaintextBytes: 4,
      recordCount: 1,
      recordIndex: 0,
      senderDeviceId: "browser-device",
      transferId: "browser-transfer",
    };
    const plaintext = Uint8Array.of(1, 2, 3, 4);
    const ciphertext = await provider.sealRecord({
      capability,
      context,
      plaintext,
    });
    const opened = await provider.openRecord({
      capability,
      ciphertext,
      context,
    });
    if (!opened.every((value, index) => value === plaintext[index]))
      throw new Error("Browser record round-trip differed.");
    await provider
      .openRecord({
        capability,
        ciphertext,
        context: { ...context, transferId: "substituted" },
      })
      .then(
        () => {
          throw new Error("Browser accepted context substitution.");
        },
        () => undefined,
      );
    return { ok: true };
  } catch (error) {
    return { error: String(error), ok: false };
  }
})();
