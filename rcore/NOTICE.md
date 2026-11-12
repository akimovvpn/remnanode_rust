# rcore source provenance

This Rust core ports a subset of [XTLS/Xray-core v26.11.9](https://github.com/XTLS/Xray-core/tree/v26.11.9), including its VLESS/Vision state machine in `proxy/proxy.go`, config, routing and management APIs. Xray-core and the REALITY additions use MPL-2.0; see `LICENSE`.

`src/reality.rs`, `src/reality_probe.rs` and `src/tls13.rs` also translate TLS logic from [XTLS/REALITY commit 4bb46b2afd8b](https://github.com/XTLS/REALITY/tree/4bb46b2afd8b), the version pinned by that Xray release. REALITY forks Go's `crypto/tls`; its Go-authored portions retain the BSD notice reproduced in `LICENSE-Go`. Both notices accompany distributions.

The TLS key schedule has RFC 8448 regression vectors. Live tests use the actual Go Xray client and local OpenSSL targets. This is an experimental subset, with the unsupported config fields and camouflage differences described in the root README. It has not had an independent cryptographic security audit.

The probe ClientHello fixtures were captured from the pinned Go Xray binary; `tests/fixtures/README.md` records their provenance. The native probe refreshes ephemeral keys and random fields. Broader fingerprint-distribution and certificate-policy differences are described in the root README.
