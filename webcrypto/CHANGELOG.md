# Changelog

## 0.1.1

- Certify compatibility with authenticated ranges, revocation, and fresh
  capability replacement in `@absolutejs/secure-transfer@0.2.x` and `0.3.x`.

## 0.1.0

- Add authenticated upload-receipt protection with a non-exportable HKDF root,
  per-receipt AES-256-GCM keys, fresh nonces, and receipt-ID binding.

## 0.0.1

- Add fresh per-transfer AES-256-GCM capabilities using browser-native WebCrypto.
- Add sequence-derived 96-bit nonces and authenticated record context.
- Add tamper and every-field context-substitution tests.
