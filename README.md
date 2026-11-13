# remnanode_rust

A Rust rewrite of [Remnawave Node](https://github.com/remnawave/node) — the management service that runs next to Xray-core and takes orders from the Remnawave panel. It speaks the same panel API, so the panel cannot tell it apart from the official Node.js node.

**Supported upstream:** Remnawave Node `3.4.5` (commit `4009f09`), bundled Xray-core `v26.11.9`.

## What it does

- All 25 panel routes (`/node/xray/*`, `/node/handler/*`, `/node/stats/*`, `/node/plugin/*`) with the same `{ "response": ... }` envelopes and error codes.
- Mutual TLS 1.3 with the panel CA, RS256 JWT on every request, optional SNI verification — all from the panel's `SECRET_KEY`.
- Starts, restarts and stops Xray; skips the restart when the user-set hashes are unchanged (same hash algorithm as upstream).
- Adds/removes VLESS, Trojan, Shadowsocks, Shadowsocks 2022 and Hysteria users over Xray's gRPC API; user/inbound/outbound traffic stats, online status, IP lists, connection drops.
- All node plugins: **torrent blocker** (Xray detects BitTorrent, the node blocks the user's IP in nftables, drops their connections and reports to the panel), ingress/egress filters, IP block/unblock with timeouts, connection-drop whitelist (IPs and CIDR ranges), shared IP and **ASN lists**, socket cleanup and post-start webhook.
- `internals.integrations` is accepted exactly like the official 3.4.5 image, which ships no integration modules.
- No JavaScript runtime. The config Xray reads is written with `0600` permissions; Xray reports torrent events over a private unix socket with a random token.

Firewall plugins and the torrent blocker need Linux, `nft` and `CAP_NET_ADMIN` (the image has `nft`; add `NET_ADMIN` in compose). Without it they are skipped with a warning, as upstream does.

## Run it

It is a drop-in replacement: in the panel's node compose file, change only the image.

```yaml
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: ghcr.io/akimovvpn/remnanode_rust:latest
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - NODE_PORT=2222
      - SECRET_KEY="paste the key from the panel"
```

```bash
docker compose pull && docker compose up -d && docker compose logs -f
```

The image is built for amd64 and arm64 and is only published after CI passes on `main`. To build it yourself instead, replace `image:` with `build: https://github.com/akimovvpn/remnanode_rust.git#main`.

| Variable | Default | Meaning |
|---|---|---|
| `NODE_PORT` | — (required) | Port the panel connects to |
| `SECRET_KEY` | — (required) | Panel-generated node secret |
| `SNI_VERIFICATION` | `false` | Reject TLS handshakes with the wrong SNI |
| `XRAY_API_ENDPOINT` | `http://127.0.0.1:61000` | Loopback address for Xray's gRPC API |
| `XRAY_BINARY` | `/usr/local/bin/xray` | Xray executable |
| `STATE_DIR` | `/var/lib/remnanode` | Private config and downloaded geodata |
| `DISABLE_HASHED_SET_CHECK` | `false` | Always restart Xray on start requests |
| `NFTABLES_TABLE_NAME` | `remnanode_rust` | nftables table owned by this node |
| `NFTABLES_LOGGING` | `true` | Log dropped packets |
| `NFTABLES_ACCEPT_REPLY_TRAFFIC` | `false` | Let reply traffic bypass ingress blocks |
| `ASN_DB_PATH` | `/usr/local/share/asn/asn-prefixes.json` | ASN prefix database ([asn-index](https://github.com/remnawave/asn-index), bundled in the image) |

## Rust core (`rcore`) — work in progress

`rcore/` is a Rust port of Xray-core **v26.11.9**, written from Xray's Go source, with Xray's CLI (`run -config`, `run -test`, `version`) and JSON config format. The image ships it next to Go Xray; switch a node to it with one variable:

```yaml
    environment:
      - XRAY_BINARY=/usr/local/bin/rcore
```

Ported and proven against real Go Xray (`rcore/tests/differential.rs` runs the node's own operations on both cores and requires identical results; `rcore/tests/interop.rs` and `vision_interop.rs` use real Go Xray VLESS clients; `outbound_interop.rs` puts rcore between a Go client and a Go server):

- gRPC API used by the node: `HandlerService` (AlterInbound add/remove user, GetInboundUsers), `StatsService` (QueryStats, GetStats, GetStatsOnline, GetStatsOnlineIpList, GetAllOnlineUsers, GetUsersStats, GetSysStats), including Xray's counter quirks.
- VLESS inbound with UDP, Vision flow rules, inbound `settings.flow` defaults inherited by clients with empty flows, and `vlessRoute`, over:
  - RAW (plain TCP, or REALITY with optional `xtls-rprx-vision`);
  - WebSocket (path/host checks, early data via `Sec-WebSocket-Protocol`, `heartbeatPeriod`, Go's 404/400/405 responses to probes);
  - HTTPUpgrade (path/host checks, early data). Unlike Go, rcore keeps early data that arrives in the same packet as the upgrade request instead of dropping it;
  - XHTTP over plain HTTP/1.1 and h2c (behind nginx/CDN) or REALITY (h2): `packet-up`, `stream-up` and `stream-one`, with the `extra` options — padding placements and `tokenish` padding, `xPaddingObfsMode`, uplink data in headers/cookies/body, GET uploads, session/seq placements and keys, `scMaxEachPostBytes`, `scMaxBufferedPosts`, `noSSEHeader`, `serverMaxHeaderBytes`. HTTP/3 (QUIC) XHTTP and `h2Params` are not supported.
- Linux outbound `streamSettings.sockopt.interface` binding and `tcpFastOpen`, including WARP interfaces; binding errors fail the connection without using the default interface.
- SOCKS5 outbound TCP and UDP with remote domain resolution and optional username/password authentication, using simplified `settings.address` / `port` / `user` / `pass` fields.
- Mux.cool and XUDP (server side): TCP and UDP sub-sessions over one VLESS connection, Vision accounts limited to UDP inside mux as in Go, and XUDP full cone — replies carry their source address and a reconnecting client keeps its outbound UDP socket for a minute. Go clients send UDP this way: always with Vision, and without flow for every port except 53 and 443. Freedom UDP uses an unconnected dual-stack socket with per-packet `finalRules` checks; SOCKS5 UDP forwards per-packet destinations.
- `sockopt.trustedXForwardedFor` for inbounds behind nginx/CDN: the client IP the node reports comes from `X-Forwarded-For`.
- Sniffing (HTTP, TLS, BitTorrent) with `destOverride`, `domainsExcluded`, `routeOnly`.
- Routing: field rules (domain incl. `geosite:`, ip incl. `geoip:`, port, network, source, user, inboundTag, protocol, local IP/port) checked in Go's condition order, `IPIfNonMatch`/`IPOnDemand` resolving through the DNS module, routing webhooks (torrent blocker).
- Balancers: `balancerTag` rules, `selector` prefixes, `fallbackTag`, and the `random`, `roundRobin`, `leastPing` and `leastLoad` (`costs`, `baselines`, `expected`, `maxRTT`, `tolerance`) strategies. `observatory` (GET probes through each outbound) and `burstObservatory` (sampled `pingConfig` health pings) feed them. As in Go, a balancer that needs observations refuses to start without an observatory.
- DNS module (`dns`): `hosts` (including domain aliases, `#rcode` answers and `useSystemHosts`), plain UDP, `tcp://`, `tcp+local://`, `https://`, `https+local://`, `h2c://` and `localhost` servers. Remote servers are routed with the DNS `tag` as the inbound tag. Also: per-server `domains`, `expectedIPs`/`unexpectedIPs` (with `*`), `skipFallback`, `finalQuery`, `clientIp` (EDNS client subnet), `queryStrategy`, `timeoutMs`, the cache with `serveStale`/`serveExpiredTTL`, `disableFallback(IfMatch)`, and `enableParallelQuery`. DoH uses the Chrome ClientHello over HTTP/2.
- Outbounds: freedom (domain strategies resolved through the DNS module, `finalRules` and the default private-IP block), blackhole, SOCKS5, VLESS, and `dns` (`rules` with direct/drop/return/hijack, legacy `nonIPQuery`/`blockTypes`, server rewrite).

`rcore/tests/dns_balancer.rs` runs the same DNS, routing and balancer config on rcore and Go Xray. Every DNS answer must match Go's byte for byte, and routing must pick the same outbounds.
- VLESS outbound (cascades), in the `vnext` or flat `address`/`port`/`id` style: RAW or WebSocket (`host`, `path` with `?ed=`, headers, Chrome browser headers like Go), with no security, TLS or REALITY; `xtls-rprx-vision` (and `-udp443`) including direct copying after inner TLS 1.3; UDP as XUDP inside mux.cool (Vision, and every port but 53/443 as Xray's cone default) or as plain VLESS UDP, keeping per-packet destinations and reply sources. TLS and REALITY send the uTLS `chrome` (default) or `firefox` ClientHello captured from Xray 26.11.9, with fresh keys, GREASE and ECH GREASE, and Chrome's extension shuffle; configured `alpn` replaces the fingerprint's, WebSocket forces `http/1.1`. Certificates are checked against Mozilla roots plus `SSL_CERT_FILE`. A REALITY server that answers with a real certificate gets Go's `spiderX` crawl and the connection fails, as in Go.

**REALITY/Vision is experimental.** Real Go Xray clients pass both X25519 and X25519MLKEM768 handshakes, unauthenticated HTTPS visitors reach the configured target, and Vision passes plain TCP plus inner TLS 1.2/1.3 transfers. The TLS 1.3 test verifies direct copying in both directions. Initial target-flight record lengths are mirrored. Native target probes now learn post-handshake record lengths and CCS tolerance using the pinned Go/Chrome 155 ClientHello templates. A local differential test requires the six handshake records and two post-handshake records to match Go REALITY exactly, then checks traffic still works. As in Go, every server name and ALPN bucket is probed in the background when the inbound starts, and results are cached per target/SNI/ALPN; only connections arriving while a probe is still running wait for it (at most 12 seconds). Failed probes finish with an empty record list and the default 32-record tolerance. Targets must provide a compatible TLS 1.3 handshake, as with upstream. REALITY targets use TCP; PROXY protocol (`xver`), fallback rate limits and the optional ML-DSA signature are explicitly rejected. The default image continues to run Go Xray.

For nonempty SNI, calibration validates the target certificate and hostname. It always verifies CertificateVerify and Finished before collecting records; empty SNI skips chain/name checks to match the pinned Go probe. It uses Mozilla roots plus optional `SSL_CERT_FILE` roots, which can differ from Go's platform trust policy. Targets requiring HelloRetryRequest, TLS 1.2 probes or unsupported certificate signature schemes (including ML-DSA) fall back without calibration. The template preserves captured GREASE values and Chrome extension order, so this is not full browser-fingerprint distribution parity. Probe reads, decompression, concurrency, replay size and wait time are bounded; replaying padding never completes a target request or sends user data to the probe target.

**Not ported yet — `rcore` refuses such configs with a named error, so keep Go Xray for them:** standalone TLS security on inbounds, XHTTP over HTTP/3, XHTTP and gRPC outbounds, gRPC transport, Shadowsocks/Trojan/Hysteria/VMess, VLESS reverse proxy and ML-KEM `encryption`, fingerprints other than `chrome`/`firefox`, TLS 1.2-only servers and HelloRetryRequest for outbound TLS/REALITY, pinned certificates, ECH configs, QUIC sniffing, fallbacks, PROXY protocol, DNS `script`, FakeDNS and DNS over QUIC (`quic+local://`). A node can use `rcore` only if every inbound and outbound in its profile is on the ported list. `GetSysStats` has no Go runtime counters to report: it returns live async tasks as goroutines, the process RSS as memory, and the exact uptime.

## Core startup diagnostics

The node starts its panel API first and waits for the panel's `/node/xray/start` request to receive the core configuration. `rcore version` only checks the installed executable. Set `XRAY_BINARY=/usr/local/bin/rcore` to select it, recreate the container, and restart the node from the panel.

Repeated `connect to Xray gRPC` warnings mean the configured API endpoint cannot be reached; they do not identify why. Check the selected executable and listening ports without printing the secret:

```sh
docker compose exec remnanode sh -c 'printf "XRAY_BINARY=%s\n" "${XRAY_BINARY:-/usr/local/bin/xray}"; printf "XRAY_API_ENDPOINT=%s\n" "${XRAY_API_ENDPOINT:-http://127.0.0.1:61000}"; ss -lntp; ls -l /var/lib/remnanode/config.json'
docker compose logs --since=5m remnanode
```

Startup logs name the selected executable. Failed start requests include the validation/process error. Core stdout/stderr is separate: run `docker exec remnanode xlogs` (or `xerrors`). Both follow `/var/log/xray/current` in the image, including rotation. See [logging details](docs/LOGGING.md). A successful start logs `Core started and gRPC is ready`. If a Rust profile uses an unsupported feature, the failure names it; use a supported test profile or switch `XRAY_BINARY` back to `/usr/local/bin/xray` and restart through the panel. Do not share `SECRET_KEY` or the contents of the generated config.

## Automatic upstream updates

`.github/workflows/upstream.yml` runs daily:

1. Checks the latest Remnawave Node release and compares every source file, dependency and pinned binary against `upstream/manifest.json`. It never runs upstream code. The report is uploaded as an Actions artifact.
2. If something changed, Claude ports the change to Rust with a read-only token. If Claude isn't configured or fails (for example, it hits a usage limit), OpenAI Codex takes over.
3. A clean job validates the patch (only the allowed Rust sources/tests (including `rcore`), Cargo manifests, `Dockerfile` and compatibility docs may change; workflows and update tooling are off limits), then runs fmt, Clippy, all tests, a real Xray smoke test and a Docker build.
4. Only if everything passes, it opens a **draft PR**. Nothing is merged or deployed automatically — review it.

Setup, under *Settings → Secrets and variables → Actions*, add one or both:

- **Claude:** `CLAUDE_CODE_OAUTH_TOKEN` (uses your Claude subscription; create it with `claude setup-token`) or `ANTHROPIC_API_KEY`.
- **Codex:** `OPENAI_API_KEY` (OpenAI API billing, separate from a ChatGPT plan).

Then enable *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*. With no keys you still get the daily drift report. Details: [docs/UPDATES.md](docs/UPDATES.md).

## Develop

```bash
cargo test --locked --workspace
python3 -m unittest discover -s scripts/tests
python3 scripts/fetch_xray.py --output /tmp/xray
XRAY_BINARY=/tmp/xray/xray cargo test --locked --workspace -- --include-ignored
docker run --rm --cap-add NET_ADMIN -v "$PWD":/src:ro -e CARGO_TARGET_DIR=/tmp/t -e NFT_TESTS=1 -w /src rust:1-slim-trixie \
  sh -c 'apt-get update -qq && apt-get install -y -qq nftables && cargo test --locked --lib real_nftables'
cargo build --locked --workspace && python3 scripts/smoke.py --binary target/debug/remnanode-rust --xray /tmp/xray/xray
python3 scripts/soak_core.py --binary target/debug/rcore    # bounded local TCP/UDP/XHTTP traffic soak
cargo bolero test -p rcore fuzz::fuzz_config           # coverage-guided; the same targets run as normal tests
```

## License

The management service is AGPL-3.0-only, same as upstream Remnawave Node. `rcore` carries MPL-2.0 and the Go TLS source BSD notice; see [rcore/NOTICE.md](rcore/NOTICE.md).
