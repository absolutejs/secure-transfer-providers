# AbsoluteJS secure-transfer providers

Interchangeable cryptographic providers for `@absolutejs/secure-transfer`.

| Package                                 | Protocol                | Runtimes           | Cost |
| --------------------------------------- | ----------------------- | ------------------ | ---- |
| `@absolutejs/secure-transfer-webcrypto` | `ABS-A256GCM-RECORDS-1` | Browser, Bun, Node | Free |

Provider packages expose the same `SecureTransferCryptoProvider` contract. The
core owns bounded transfer orchestration and untrusted-store semantics; providers
own record cryptography and capability format.

Run `bun run check:package` for the complete workspace gate and `bun run
certify:browser` for the executable Chromium round-trip and context-substitution
gate.

## License

Apache-2.0
