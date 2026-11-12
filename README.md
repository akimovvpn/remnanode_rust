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

Ported and proven against real Go Xray (`rcore/tests/differential.rs` runs the node's own operations on both cores and requires identical results; `rcore/tests/interop.rs` uses a real Go Xray VLESS client):

- gRPC API used by the node: `HandlerService` (AlterInbound add/remove user, GetInboundUsers), `StatsService` (QueryStats, GetStats, GetStatsOnline, GetStatsOnlineIpList, GetAllOnlineUsers, GetUsersStats, GetSysStats), including Xray's counter quirks.
- VLESS inbound with UDP, Vision flow rules and `vlessRoute`, over:
  - RAW (plain TCP, no TLS);
  - WebSocket (path/host checks, early data via `Sec-WebSocket-Protocol`, `heartbeatPeriod`, Go's 404/400/405 responses to probes);
  - HTTPUpgrade (path/host checks, early data). Unlike Go, rcore keeps early data that arrives in the same packet as the upgrade request instead of dropping it.
- `sockopt.trustedXForwardedFor` for inbounds behind nginx/CDN: the client IP the node reports comes from `X-Forwarded-For`.
- Sniffing (HTTP, TLS, BitTorrent) with `destOverride`, `domainsExcluded`, `routeOnly`.
- Routing: field rules (domain incl. `geosite:`, ip incl. `geoip:`, port, network, source, user, inboundTag, protocol, local IP/port), `IPIfNonMatch`/`IPOnDemand`, routing webhooks (torrent blocker).
- Outbounds: freedom (domain strategies, `finalRules` and the default private-IP block) and blackhole.

**Not ported yet — `rcore` refuses such configs with a named error, so keep Go Xray for them:** REALITY and TLS security, XHTTP, gRPC transport, Shadowsocks/Trojan/Hysteria/VMess, mux/XUDP (Go clients use it for UDP), QUIC sniffing, fallbacks, PROXY protocol, VLESS outbounds (cascades), DNS, balancers. A node can use `rcore` only if every inbound in its profile is on the ported list; profiles that mix in REALITY or XHTTP still need Go Xray. `GetSysStats` reports OS memory figures because Go runtime counters have no Rust equivalent.

## Automatic upstream updates

`.github/workflows/upstream.yml` runs daily:

1. Checks the latest Remnawave Node release and compares every source file, dependency and pinned binary against `upstream/manifest.json`. It never runs upstream code. The report is uploaded as an Actions artifact.
2. If something changed, Claude ports the change to Rust with a read-only token. If Claude isn't configured or fails (for example, it hits a usage limit), OpenAI Codex takes over.
3. A clean job validates the patch (only `src/`, `tests/`, `proto/`, `Cargo.*`, `Dockerfile` and docs may change; workflows and update tooling are off limits), then runs fmt, Clippy, all tests, a real Xray smoke test and a Docker build.
4. Only if everything passes, it opens a **draft PR**. Nothing is merged or deployed automatically — review it.

Setup, under *Settings → Secrets and variables → Actions*, add one or both:

- **Claude:** `CLAUDE_CODE_OAUTH_TOKEN` (uses your Claude subscription; create it with `claude setup-token`) or `ANTHROPIC_API_KEY`.
- **Codex:** `OPENAI_API_KEY` (OpenAI API billing, separate from a ChatGPT plan).

Then enable *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*. With no keys you still get the daily drift report. Details: [docs/UPDATES.md](docs/UPDATES.md).

## Develop

```bash
cargo test --locked
python3 -m unittest discover -s scripts/tests
python3 scripts/fetch_xray.py --output /tmp/xray
XRAY_BINARY=/tmp/xray/xray cargo test --locked -- --include-ignored
docker run --rm --cap-add NET_ADMIN -v "$PWD":/src:ro -e CARGO_TARGET_DIR=/tmp/t -e NFT_TESTS=1 -w /src rust:1-slim-trixie \
  sh -c 'apt-get update -qq && apt-get install -y -qq nftables && cargo test --locked --lib real_nftables'
cargo build --locked && python3 scripts/smoke.py --binary target/debug/remnanode-rust --xray /tmp/xray/xray
```

## License

AGPL-3.0-only, same as upstream Remnawave Node.
