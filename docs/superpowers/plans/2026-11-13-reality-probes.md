# REALITY target probing implementation plan

**Goal:** Add bounded native target probes and replay target post-handshake record lengths; learn CCS limits without changing the default Go engine.
**Architecture:** Probe TLS1.3 using pinned ClientHello fingerprints, fresh ephemeral keys and verified target handshake. Cache by target/SNI/ALPN. Replay learned encrypted empty records after authenticated Finished; apply learned CCS bounds. Probe failures resolve to empty results without hanging clients.
**Tech stack:** Existing Rust/Tokio, TLS key schedule and crypto; installed TLS certificate validation dependencies.
**Scope:** rcore/src/reality_probe.rs (native client/probes), reality.rs (cache/replay/CCS), tls13.rs (explicit learned bound), app.rs/main.rs (wire initialization), focused unit/live integration tests, Cargo manifests if existing transitive libraries needed, README/NOTICE.

- [x] Establish pinned Go probe behavior and exact ClientHello fingerprint sources.
- [x] Write failing tests for record gathering, CCS thresholds, cache/timeout and replay.
- [x] Implement minimal native probes with bounded time/memory/concurrency; verify certificates/Finished; no subprocess in runtime.
- [x] Integrate replay and CCS bounds; preserve ordinary TLS/Vision flow and default Go core.
- [ ] Compare local target results with pinned Go behavior; full Rust/Python checks and Linux integration.
- [ ] Independent review, commit, push and verify CI.

No broad cipher/protocol additions, production rollout, external untrusted target testing, or silent full-camouflage claim. Exact differences must remain documented. Existing user publication authorization applies.

## Verification and review

- 119 native Rust workspace tests (including real Go interop/differential), 12 Python tests, Clippy and formatter pass.
- Go/Rust record comparison: six equal handshake records and two 255-byte post-handshake records, followed by working echo traffic.
- Review fixed replay backpressure timeout and ECH public-key/config-id generation; cache waiter cancellation/deadline regression fixed RED→GREEN.
- Operator-reported startup failure reproduced: retired `routing.domainMatcher` was wrongly rejected. Pinned Go accepts it without effect; Rust now matches at routing/rule levels, with regression and live differential fixtures. Core start failures and selected executable are now logged.
- Remaining documented limits: TLS1.2/HRR probes, unsupported signature schemes, trust-store differences, fixed captured GREASE/extension-order distribution; Go remains default.
