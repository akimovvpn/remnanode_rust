# Pinned REALITY probe ClientHellos

These are the original TLS handshake bytes (type 1, three-byte length, body),
without the five-byte TLS record header, captured from the actual startup
`DetectPostHandshakeRecordsLens` probes of Xray 26.11.9 on darwin/arm64.

The executable reports `Xray 26.11.9 ... 676eaf6 (go1.27.3 darwin/arm64)`.
Its SHA-256 is
`1b2d5ebe3a4c332203db24b81a052c6d6688a7f80705090f031b7416013ee1b2`.
The release pins [REALITY 4bb46b2afd8b](https://github.com/XTLS/REALITY/tree/4bb46b2afd8b)
and [uTLS a13c59ffe98b](https://github.com/refraction-networking/utls/tree/a13c59ffe98b).
At this uTLS revision `HelloChrome_Auto` is `HelloChrome_155`.

| File | Detector ALPN bucket | Fingerprint | Offered ALPN |
| --- | --- | --- | --- |
| `clienthello-golang.bin` | 0 | `HelloGolang` | absent |
| `clienthello-golang-http1.bin` | 1 | `HelloGolang` | `http/1.1` |
| `clienthello-chrome155.bin` | 2 | `HelloChrome_Auto` | `h2`, `http/1.1` |

Capture procedure: configure a loopback VLESS REALITY inbound with one server
name, `probe.example`, and its target pointing to a loopback TCP capture socket.
Starting the inbound launches six probes (two per ALPN bucket); save the first
ClientHello in each bucket and close the capture connections. No TLS target,
certificate bypass, outbound connection, or Go compiler is needed. Each capture
arrived in one handshake record with legacy record version `0x0301`.

Randoms, session IDs, ephemeral public keys, GREASE values, ECH payloads, and
Chrome extension order are snapshots. A live probe must generate its own keys,
replace both X25519 shares, update the SNI and nested lengths, and
hash the bytes it actually sends. These fixtures establish pinned structure;
they do not establish fresh Chrome randomness or extension-order distribution.
The Go captures reuse the X25519 public key across both shares; Chrome uses
different public keys in its hybrid and standalone shares.

Do not use the older uTLS version in a developer's Go module cache as the
reference for this release.
