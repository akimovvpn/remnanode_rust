# XHTTP downloadSettings implementation plan

**Goal:** Port the pinned Go Xray v26.11.9 separate XHTTP download leg so existing configurations can run on Rust.

**Scope:** Nested stream parsing, independent destination/security/socket settings, request formatting, shared session identity, Go auto-mode selection and XMUX accounting. Reuse the existing HTTP/1.1/HTTP/2, TLS/REALITY and request code. HTTP/3 and other unported transport options remain named errors.

## Tasks

- [x] Add failing parser and runtime tests for effective `extra`, nested settings, mode selection and independent per-leg state.
- [x] Parse the child stream using existing TLS/REALITY and socket parsers; preserve Go's method/network and settings aliases. Reject missing destinations and non-XHTTP download streams with clear errors instead of Go's runtime panics.
- [x] Use child request settings, destination and pool for GET only; share the upload-generated session ID. REALITY auto becomes stream-up when a separate download leg exists. Keep packet rotation on the upload manager.
- [x] Prove TCP and UDP through two distinct reverse-proxy frontends into one real Go XHTTP server; assert requests reach their configured leg with its own path/query/headers/security.
- [x] Independently review against pinned Go; run Linux workspace tests with Go, Clippy, formatting, Python tests and both node smoke tests.
- [ ] Update support documentation, commit and push; follow CI and verify published amd64/arm64 tags.

## Source decisions

- Go replaces advanced fields with `extra` when it is present, including explicit null; only outer host/path/mode survive.
- Child path and query both replace parent values. Child security defaults independently to plaintext.
- Nested descendants are parsed/validated, but GET selection uses only the immediate child.
- Child socket settings apply unless parent `sockopt.penetrate` replaces the entire socket configuration.
- User authorization covers implementation and publication; no new policy or feature design is required.

## Verification notes

- Source review caught and corrected case-insensitive nested stream fields, address normalization/environment expansion and unused server-side download settings.
- The Linux REALITY fixture exposed a Go raw dokodemo-door splice issue: Go-to-Go reproduced the same invalid TLS record as Rust-to-Go. Disabling Go splice only on that fixture's raw REALITY tunnel restored both reference and Rust tests; production splice behavior is unchanged.
- Hold dynamically allocated test ports until their owning process launches, preventing ephemeral connections from claiming them during configuration validation. Readiness also requires the owning child's startup message; a bare TCP probe could succeed before that child started while a concurrent fork briefly held the reservation.

- Final local Linux verification: Clippy with warnings denied; 288 Rust tests against pinned Go, zero failures/ignored; 12 Python tests; formatting/artifact-pin checks; node smoke tests with both Go Xray and rcore. All five separate-download interop cases also passed five consecutive runs (25 checks).
