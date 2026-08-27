import type { SecureTransferReceiptProtector } from "@absolutejs/secure-transfer";

export type SecureTransferWebcryptoReceiptProtectorOptions = {
  /** HKDF root key, or exactly 32 random bytes imported as a non-exportable key. */
  readonly key: CryptoKey | Uint8Array;
  readonly id?: string;
};

const VERSION = 1;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const ROOT_KEY_BYTES = 32;
const DEFAULT_ID = "secure-transfer.receipts.webcrypto.hkdf-aes-gcm";

export class SecureTransferReceiptProtectionError extends Error {
  override readonly name = "SecureTransferReceiptProtectionError";
}

const ownedBuffer = (bytes: Uint8Array): ArrayBuffer =>
  Uint8Array.from(bytes).buffer;

const requireReceiptId = (receiptId: string): void => {
  const length = new TextEncoder().encode(receiptId).length;
  if (length < 1 || length > 512)
    throw new SecureTransferReceiptProtectionError(
      "receiptId must contain between 1 and 512 UTF-8 bytes.",
    );
};

const rootKeyFor = async (key: CryptoKey | Uint8Array): Promise<CryptoKey> => {
  if (key instanceof Uint8Array) {
    if (key.length !== ROOT_KEY_BYTES)
      throw new SecureTransferReceiptProtectionError(
        "Receipt protection root key must contain exactly 32 bytes.",
      );
    return crypto.subtle.importKey("raw", ownedBuffer(key), "HKDF", false, [
      "deriveKey",
    ]);
  }
  if (
    key.type !== "secret" ||
    key.algorithm.name !== "HKDF" ||
    key.extractable ||
    !key.usages.includes("deriveKey")
  )
    throw new SecureTransferReceiptProtectionError(
      "Receipt protection CryptoKey must be a non-exportable HKDF deriveKey secret.",
    );
  return key;
};

const aadFor = (id: string, receiptId: string): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify({
      contract: 1,
      protectorId: id,
      purpose: "absolutejs.secure-transfer.upload-receipt",
      receiptId,
    }),
  );

const derivedKeyFor = async (
  rootKey: CryptoKey,
  id: string,
  receiptId: string,
): Promise<CryptoKey> => {
  const salt = await crypto.subtle.digest(
    "SHA-256",
    ownedBuffer(new TextEncoder().encode(id)),
  );
  return crypto.subtle.deriveKey(
    {
      hash: "SHA-256",
      info: ownedBuffer(new TextEncoder().encode(receiptId)),
      name: "HKDF",
      salt,
    },
    rootKey,
    { length: 256, name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"],
  );
};

export const createSecureTransferWebcryptoReceiptProtector = async (
  options: SecureTransferWebcryptoReceiptProtectorOptions,
): Promise<SecureTransferReceiptProtector> => {
  const id = options.id ?? DEFAULT_ID;
  if (id.trim().length === 0)
    throw new SecureTransferReceiptProtectionError(
      "Receipt protector id must not be empty.",
    );
  const rootKey = await rootKeyFor(
    options.key instanceof Uint8Array ? options.key.slice() : options.key,
  );

  const protector: SecureTransferReceiptProtector = {
    id,
    open: async ({ protectedBytes, receiptId }) => {
      requireReceiptId(receiptId);
      if (
        protectedBytes.length <= 1 + NONCE_BYTES + TAG_BYTES ||
        protectedBytes[0] !== VERSION
      )
        throw new SecureTransferReceiptProtectionError(
          "Protected receipt framing is invalid.",
        );
      const nonce = protectedBytes.slice(1, 1 + NONCE_BYTES);
      const ciphertext = protectedBytes.slice(1 + NONCE_BYTES);
      try {
        return new Uint8Array(
          await crypto.subtle.decrypt(
            {
              additionalData: ownedBuffer(aadFor(id, receiptId)),
              iv: ownedBuffer(nonce),
              name: "AES-GCM",
              tagLength: 128,
            },
            await derivedKeyFor(rootKey, id, receiptId),
            ownedBuffer(ciphertext),
          ),
        );
      } catch (cause) {
        throw new SecureTransferReceiptProtectionError(
          `Protected receipt authentication failed: ${String(cause)}`,
        );
      }
    },
    protect: async ({ plaintext, receiptId }) => {
      requireReceiptId(receiptId);
      if (plaintext.length === 0)
        throw new SecureTransferReceiptProtectionError(
          "Receipt plaintext must not be empty.",
        );
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            additionalData: ownedBuffer(aadFor(id, receiptId)),
            iv: ownedBuffer(nonce),
            name: "AES-GCM",
            tagLength: 128,
          },
          await derivedKeyFor(rootKey, id, receiptId),
          ownedBuffer(plaintext),
        ),
      );
      const protectedBytes = new Uint8Array(
        1 + NONCE_BYTES + ciphertext.length,
      );
      protectedBytes[0] = VERSION;
      protectedBytes.set(nonce, 1);
      protectedBytes.set(ciphertext, 1 + NONCE_BYTES);
      return protectedBytes;
    },
  };
  return Object.freeze(protector);
};
