# XHTTP outbound implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. The user has authorized continuing the pinned Go port and publication.

**Goal:** Carry VLESS outbound TCP and UDP over the pinned Go XHTTP client protocol.

**Architecture:** Reuse the existing socket dialer, TLS/REALITY handshake and XHTTP configuration/padding helpers. Add request formatting and a streaming HTTP client; keep VLESS encoding and accounting in the existing outbound wrapper. Reuse clients by outbound identity and apply Go's XMUX selection and lifetime rules.

**Tech stack:** Existing Tokio, Hyper 1, http-body-util and bytes dependencies.

**Spec:** AGENTS.md and Xray-core v26.11.9 transport/internet/splithttp/{dialer,client,config,mux,xpadding,connection}.go.

## Constraints

- Preserve Go's defaults, request shapes, mode/HTTP-version selection and asynchronous response handling.
- No invented quotas, options, timeouts or protocol extensions.
- Keep HTTP/3, separate downloadSettings and h2Params explicitly unsupported until ported.
- Preserve existing VLESS accounting, TLS certificate verification and socket settings.
- Existing user authorization covers implementation, tests, push and publication.

## Review focus

- Opening a stream must return before response headers; delayed upload must not deadlock.
- Transitioning request bodies to EOF must preserve the response and drain upload-only responses.
- Packet dispatch must wait for writes, not response completion; interval and size come from Go settings.
- Preserve base queries, header/cookie payload encoding and pre-metadata padding URLs.
- XMUX retirement must let existing streams finish and must rotate packet clients when exhausted.

## Tasks

### 1. Request configuration and formatting

- [x] Add failing unit tests for normalized defaults, query/metadata ordering, chunk encoding and XMUX's all-zero default bundle.
- [x] Implement `rcore/src/xhttp_request.rs` using the existing XHTTP parser and padding helpers.
- [x] Run the focused unit tests; compare emitted requests with pinned Go behavior.

### 2. Transport and VLESS integration

- [x] Add real Go-server fixture profiles in `rcore/tests/outbound_interop.rs`; observe rejection of XHTTP outbound on the old implementation.
- [x] Implement `rcore/src/xhttp_client.rs`: H1/H2 selection, streaming bodies, packet batching, raw H1 packet pool, shared H2 clients and XMUX rotation.
- [x] Integrate `Network::Xhttp` in `rcore/src/vless_out.rs`, parser support in `rcore/src/config.rs` and modules in `rcore/src/main.rs`.
- [x] Pass real Go interoperability cases for auto/packet-up, stream-up, stream-one, TLS, REALITY and obfuscated metadata/payload placements.

### 3. Verify and publish

- [x] Review cancellation, EOF, HTTP status handling, connection reuse and request accounting against Go.
- [x] Update README's supported and unported lists accurately.
- [x] Run formatting, Clippy, full Linux workspace tests with pinned Go, Python tests and both node smoke tests.
- [x] Obtain independent source-parity review; fix demonstrated issues and rerun relevant checks.
- [ ] Commit, push, follow CI and image publication, verify both architecture manifests and tag identity.

## Execution record

- Base: b87bd578a9d6bbbe7a315a497a4e28c98a6c34b3.
- RED: `xhttp_http_packet_up` fails because rcore rejects `outbounds[0].streamSettings.xhttpSettings`.

- Source rulings: H1 packet serialization triggers `WroteRequest` before socket writes, matching Go; raw upload pools use per-worker private items and a stealable shared deque. No response-draining policy was added to that raw pool.
- Fixture root cause: the inner TLS client must flush final ciphertext before waiting for its echoed payload. Both Go and Rust reproduced the timeout without that flush and passed the same bridged fixture after it.
- Review regressions: low peer stream capacity opens another H2 connection; replayable packets retry REFUSED_STREAM/graceful GOAWAY, while fatal first-stream GOAWAY returns immediately; redirects preserve Go method/body/header rules and URL authentication.
- Focused tests cover gzip, response errors, partial upload/response lifetimes, metadata/headers and connection retirement. Independent final review of HTTP/2 and redirects found no remaining actionable issues.
- XHTTP performance and a real VPS deployment have not been measured in this continuation.
- Final local verification: 268 Linux tests with pinned Go (zero ignored/failures), all 15 macOS outbound interop tests, 12 Python tests, fmt/Clippy, compatibility pins, and node smoke tests with both Go and Rust cores passed.
