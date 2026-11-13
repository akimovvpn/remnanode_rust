# Mihomo REALITY compatibility implementation plan

**Goal:** Restore authenticated legacy REALITY clients by default, as explicitly selected by the user on 2026-11-14.

**Design:** Restore the Go REALITY `9234c772ba8f` authentication-key selection: standalone X25519 first, then the X25519 component of a hybrid share. This deliberately replaces the mandatory hybrid/order gate added in `8cdf7bf9c7f0`; it also restores historical first-valid duplicate handling. Keep TLS/SNI, authenticated ClientHello, contributory key, short-ID, version/time constraints and target fallback unchanged. No new setting, protocol or dependency.

**Approaches:** Client-side hybrid support plus a suitable fingerprint can work with strict upstream, but does not help older app cores. An opt-in server exception preserves strict defaults but requires configuration; the user chose compatibility enabled by default instead. Hybrid negotiation remains available when offered and selected by the target. Legacy clients can negotiate classical-only TLS and have older browser fingerprints.

## Files and checks

- [x] `rcore/src/reality.rs`: add failing authenticated legacy, key precedence and negative authentication tests; restore the historical selector and pass them.
- [x] `rcore/tests/vision_interop.rs`: reuse the existing target/TCP/TLS/XUDP fixtures with pinned real Mihomo clients. Prove legacy failure before the fix and successful RAW+Vision and XHTTP afterward; retain modern Go tests and test modern Mihomo hybrid support.
- [x] `scripts/fetch_mihomo.py` and CI: fetch the fixed official release v1.19.34, verify pinned SHA256 before execution, run actual client tests in CI.
- [x] `docs/MIHOMO.md`, README and project contract: record upstream sources, the approved exception, applicable profile settings and limits. No claim that every client/protocol/version works.
- [x] Independent source/security review; Linux Clippy/workspace/Go/Mihomo tests, Python tests, formatting and both node smokes.
- [ ] Commit/push; require green CI; verify published amd64/arm64 tags.

## Evidence

- https://f.docs.rw/t/topic/852: failures persist with `minClientVer: "0.0.0"`; fingerprint and hybrid support vary with bundled core.
- https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f0: mandatory hybrid ClientHello rule.
- https://github.com/MetaCubeX/mihomo/blob/v1.19.34/component/tls/reality.go: hybrid is removed unless explicitly enabled; advertised client version is 1.8.2.
- https://github.com/XTLS/REALITY/blob/9234c772ba8f/tls.go: historical two-pass authentication-key selection.

## Fixture findings

- Mihomo opens SOCKS before finishing initialization and silently closes external connections until `OnRunning`. A successful SOCKS greeting/CONNECT is not readiness. Its `-post-up` hook runs after initialization; the fixture waits for a unique marker from that hook without retrying compatibility traffic. Source: https://github.com/MetaCubeX/mihomo/blob/v1.19.34/hub/executor/executor.go and https://github.com/MetaCubeX/mihomo/blob/v1.19.34/main.go .
- Go Vision switches its writer only on a complete TLS-record buffer. Bulk OpenSSL writes do not guarantee that boundary, and Go's bounded asynchronous logger can drop debug markers. Isolated TLS warmup checks both direct-copy markers before the bulk transfer, retaining the original assertion.

## Verification results

- Three authenticated legacy/key-selection tests failed before the production change; the real Mihomo client also fell through to the target certificate before the change.
- All 16 Go/Mihomo Vision/XHTTP cases passed five consecutive complete runs after the source-backed readiness correction (80 checks).
- Linux workspace: Clippy with warnings denied, 299 Rust tests with pinned Go and Mihomo, zero failed/ignored, successful workspace build. Python downloader was validated separately in the Python-equipped Linux smoke container because the Rust build image has no Python.
- 13 Python tests, formatting/artifact pins, and both Go-core/Rust-core node smokes passed. The official pinned Mihomo release was downloaded, checksum-verified and executed successfully.
- Independent source/security and final diff reviews found no blockers.
