# jwt-lab

Experimental Rust JWT CLI in the [Localzet token family](https://github.com/topics/localzet-tokens). See the primary [Russian documentation](README.md).

The working CLI uses `jsonwebtoken` and supports HS256 only. Verification checks signature, expiration with zero leeway and issuer `jwtgate`. Inspection is explicitly unverified. The LWT envelope and additional algorithms in draft modules are not implemented by the CLI.

```bash
cargo test --locked --all-targets
cargo build --locked --release
./target/release/jwt-lab --key /secure/path/jwtgate.key init
./target/release/jwt-lab --key /secure/path/jwtgate.key issue --sub alice --ttl 3600 --role reader
./target/release/jwt-lab --key /secure/path/jwtgate.key verify '<token>'
./target/release/jwt-lab inspect '<token>'
```

Initialization generates a 256-bit random key using exclusive file creation. Existing files are preserved. Unix files request mode 0600; use a filesystem enforcing Unix permissions, or configure Windows ACLs. Keys are ignored by Git. Token arguments can enter shell history; use demonstration tokens for manual tests.

Verified with Rust 1.98.1. Four tests cover an RFC 4231 HMAC vector, issue/verify, rejection of wrong keys/algorithms/issuers/expired tokens and exclusive key creation.

Remaining work: specify LWT format and threat model; isolate and verify unused draft JOSE models; add application audience/authorization policy; add interoperability and fuzz tests. This is research work, not a production SDK. License: [AGPL-3.0](LICENSE).

## Attribution

Maintainer of Localzet contributions: **Ivan Zorin (localzet)** — <creator@localzet.com> · https://www.localzet.com. Copyright © 2026 Localzet Group. Original authorship and third-party licenses remain applicable. See [AUTHORS](.github/AUTHORS.md).
