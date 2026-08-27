# Security policy

This provider is experimental and has not received an independent security
audit. Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/secure-transfer-providers`.

Never log or store a transfer capability outside its E2EE-protected descriptor.
Every capability must be used for exactly one transfer. Applications must enforce
the limits and transactional sink requirements from `@absolutejs/secure-transfer`.

Receipt protection requires a separate 32-byte random root key. Store it in a
platform keystore, do not use a password directly, and do not reuse a transfer
content key. Receipt IDs are authenticated and used in per-receipt HKDF key
derivation.
