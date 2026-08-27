# `@absolutejs/secure-transfer-webcrypto`

Interchangeable WebCrypto provider for `@absolutejs/secure-transfer`. Each
transfer receives fresh random AES-256-GCM key material and a 96-bit nonce base.
Every record nonce is derived by XORing that base with the record sequence,
following the construction used by RFC 8188. Record metadata is authenticated as
additional data.

```ts
import { createSecureTransferWebcryptoProvider } from "@absolutejs/secure-transfer-webcrypto";

const cryptoProvider = createSecureTransferWebcryptoProvider();
```

Protect resumable-upload receipts with a separate root key:

```ts
const receiptProtector = await createSecureTransferWebcryptoReceiptProtector({
  key: crypto.getRandomValues(new Uint8Array(32)),
});
```

Persist that root key in a platform keystore rather than regenerating it. It is
imported as a non-exportable HKDF key, derives an isolated AES-256-GCM key for
each receipt ID, and uses a fresh 96-bit nonce for every checkpoint. Do not reuse
the transfer content key as the receipt root key.

The capability contains the content key and nonce base. It is a bearer secret and
must only appear inside an E2EE-protected transfer descriptor. This provider does
not store or distribute capabilities.

The provider caps plaintext records at 16 MiB and the number of records at
1,048,576. Applications should normally choose smaller records for bounded memory
and resumability.

This is an experimental `0.x` release without an independent audit.
Run `bun run certify:browser` from the repository root to repeat the real
Chromium round-trip and context-substitution gate.

## License

Apache-2.0
