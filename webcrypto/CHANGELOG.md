# Changelog

## 0.1.0

- Add authenticated upload-receipt protection with a non-exportable HKDF root,
  per-receipt AES-256-GCM keys, fresh nonces, and receipt-ID binding.

## 0.0.1

- Add fresh per-transfer AES-256-GCM capabilities using browser-native WebCrypto.
- Add sequence-derived 96-bit nonces and authenticated record context.
- Add tamper and every-field context-substitution tests.
