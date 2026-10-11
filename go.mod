// SopsHQ - self-hosted SOPS/age key management control plane.
//
// Dependency policy: standard library first. A third-party module is added only
// when it is clearly more correct, professional, or future-proof than hand-rolling,
// and then it must be small, audited, pure-Go, with minimal transitive deps (each
// addition justified in the commit message). Today the only such module is
// rsc.io/qr (a pure-Go QR encoder with zero transitive deps) for the TOTP
// enrollment QR. Cryptography, web, and storage are stdlib; the external programs
// invoked are the installed `age-keygen`/`sops` and `setfacl`/`getfacl` binaries.
module sopshq

go 1.27

require rsc.io/qr v0.2.0
