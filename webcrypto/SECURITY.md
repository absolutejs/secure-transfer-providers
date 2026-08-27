# Security policy

This provider is experimental and has not received an independent security
audit. Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/secure-transfer-providers`.

Never log or store a transfer capability outside its E2EE-protected descriptor.
Every capability must be used for exactly one transfer. Applications must enforce
the limits and transactional sink requirements from `@absolutejs/secure-transfer`.
