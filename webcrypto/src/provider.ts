import type {
  SecureTransferCapability,
  SecureTransferCryptoProvider,
  SecureTransferRecordContext,
} from "@absolutejs/secure-transfer";
import { secureTransferWebcryptoProviderManifest } from "./provider-manifest";

const CAPABILITY_BYTES = 45;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAXIMUM_RECORD_PLAINTEXT_BYTES = 16 * 1024 * 1024;
const MAXIMUM_RECORDS = 1_048_576;

export class SecureTransferWebcryptoError extends Error {
  override readonly name = "SecureTransferWebcryptoError";
}

const validateContext = (context: SecureTransferRecordContext): void => {
  if (
    context.attachmentId.trim().length === 0 ||
    context.conversationId.trim().length === 0 ||
    context.senderDeviceId.trim().length === 0 ||
    context.transferId.trim().length === 0 ||
    !Number.isSafeInteger(context.expiresAt) ||
    !Number.isSafeInteger(context.plaintextBytes) ||
    context.plaintextBytes < 1 ||
    context.plaintextBytes > MAXIMUM_RECORD_PLAINTEXT_BYTES ||
    !Number.isSafeInteger(context.recordCount) ||
    context.recordCount < 1 ||
    context.recordCount > MAXIMUM_RECORDS ||
    !Number.isSafeInteger(context.recordIndex) ||
    context.recordIndex < 0 ||
    context.recordIndex >= context.recordCount ||
    context.final !== (context.recordIndex === context.recordCount - 1)
  )
    throw new SecureTransferWebcryptoError(
      "Authenticated record context is invalid.",
    );
};

const validateCapability = (
  capability: SecureTransferCapability,
): Uint8Array => {
  if (
    capability.providerId !== secureTransferWebcryptoProviderManifest.id ||
    capability.protocol !== secureTransferWebcryptoProviderManifest.protocol ||
    capability.bytes.length !== CAPABILITY_BYTES ||
    capability.bytes[0] !== 1
  )
    throw new SecureTransferWebcryptoError(
      "Transfer capability is invalid or belongs to another provider.",
    );
  return capability.bytes;
};

const additionalData = (context: SecureTransferRecordContext): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify({
      attachmentId: context.attachmentId,
      conversationId: context.conversationId,
      expiresAt: context.expiresAt,
      final: context.final,
      plaintextBytes: context.plaintextBytes,
      recordCount: context.recordCount,
      recordIndex: context.recordIndex,
      senderDeviceId: context.senderDeviceId,
      transferId: context.transferId,
    }),
  );

const nonceFor = (capability: Uint8Array, recordIndex: number): Uint8Array => {
  const nonce = capability.slice(1 + KEY_BYTES);
  let sequence = BigInt(recordIndex);
  for (let index = NONCE_BYTES - 1; index >= 0; index -= 1) {
    nonce[index] = (nonce[index] ?? 0) ^ Number(sequence & 0xffn);
    sequence >>= 8n;
  }
  return nonce;
};

const keyFor = (capability: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    "raw",
    capability.slice(1, 1 + KEY_BYTES),
    { name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"],
  );

const ownedBuffer = (bytes: Uint8Array): ArrayBuffer =>
  Uint8Array.from(bytes).buffer;

export const createSecureTransferWebcryptoProvider =
  (): SecureTransferCryptoProvider =>
    Object.freeze({
      createCapability: async () => {
        const bytes = crypto.getRandomValues(new Uint8Array(CAPABILITY_BYTES));
        bytes[0] = 1;
        return Object.freeze({
          bytes,
          protocol: secureTransferWebcryptoProviderManifest.protocol,
          providerId: secureTransferWebcryptoProviderManifest.id,
        });
      },
      id: secureTransferWebcryptoProviderManifest.id,
      maximumRecordCiphertextBytes: MAXIMUM_RECORD_PLAINTEXT_BYTES + TAG_BYTES,
      maximumRecordPlaintextBytes: MAXIMUM_RECORD_PLAINTEXT_BYTES,
      openRecord: async ({ capability, ciphertext, context }) => {
        validateContext(context);
        const bytes = validateCapability(capability);
        if (
          ciphertext.length !== context.plaintextBytes + TAG_BYTES ||
          ciphertext.length > MAXIMUM_RECORD_PLAINTEXT_BYTES + TAG_BYTES
        )
          throw new SecureTransferWebcryptoError(
            "Encrypted record length is invalid.",
          );
        try {
          return new Uint8Array(
            await crypto.subtle.decrypt(
              {
                additionalData: ownedBuffer(additionalData(context)),
                iv: ownedBuffer(nonceFor(bytes, context.recordIndex)),
                name: "AES-GCM",
                tagLength: 128,
              },
              await keyFor(bytes),
              ownedBuffer(ciphertext),
            ),
          );
        } catch (cause) {
          throw new SecureTransferWebcryptoError(
            `Encrypted record authentication failed: ${String(cause)}`,
          );
        }
      },
      protocol: secureTransferWebcryptoProviderManifest.protocol,
      sealRecord: async ({ capability, context, plaintext }) => {
        validateContext(context);
        const bytes = validateCapability(capability);
        if (plaintext.length !== context.plaintextBytes)
          throw new SecureTransferWebcryptoError(
            "Plaintext record length does not match authenticated context.",
          );
        return new Uint8Array(
          await crypto.subtle.encrypt(
            {
              additionalData: ownedBuffer(additionalData(context)),
              iv: ownedBuffer(nonceFor(bytes, context.recordIndex)),
              name: "AES-GCM",
              tagLength: 128,
            },
            await keyFor(bytes),
            ownedBuffer(plaintext),
          ),
        );
      },
    });
