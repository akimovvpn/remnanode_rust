# remnanode_rust

A Rust rewrite of [Remnawave Node](https://github.com/remnawave/node) — the management service that runs next to Xray-core and takes orders from the Remnawave panel. It speaks the same panel API, so the panel cannot tell it apart from the official Node.js node.

**Supported upstream:** Remnawave Node `3.4.5` (commit `4009f09`), bundled Xray-core `v26.11.9`.

## What it does

- All 25 panel routes (`/node/xray/*`, `/node/handler/*`, `/node/stats/*`, `/node/plugin/*`) with the same `{ "response": ... }` envelopes and error codes.
- Mutual TLS 1.3 with the panel CA, RS256 JWT on every request, optional SNI verification — all from the panel's `SECRET_KEY`.
- Starts, restarts and stops Xray; skips the restart when the user-set hashes are unchanged (same hash algorithm as upstream).
- Adds/removes VLESS, Trojan, Shadowsocks, Shadowsocks 2022 and Hysteria users over Xray's gRPC API; user/inbound/outbound traffic stats, online status, IP lists, connection drops.
- nftables plugins: ingress/egress filters, IP block/unblock with timeouts, connection-drop whitelist, socket cleanup and post-start webhook.
- No JavaScript runtime. The config Xray reads is written with `0600` permissions.

## Not supported (fails loudly, never pretends)

- Torrent blocker plugin — sync is rejected; `collect` returns no reports.
- ASN shared lists inside plugin rules, CIDR ranges in connection-drop whitelists.
- Non-empty `internals.integrations` in `/node/xray/start`.

If your panel config uses one of these, keep the official node on that server.

## Run it

1. In the panel, create the node and copy its `SECRET_KEY`.
2. On the server:

```bash
git clone https://github.com/akimovvpn/remnanode_rust.git && cd remnanode_rust
cp .env.example .env   # paste SECRET_KEY, set NODE_PORT
docker compose up -d --build
```

Uncomment `cap_add: [NET_ADMIN]` in `compose.yaml` if you use firewall plugins, IP blocking or connection drops.

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

## Automatic upstream updates

`.github/workflows/upstream.yml` runs daily:

1. Checks the latest Remnawave Node release and compares every source file, dependency and pinned binary against `upstream/manifest.json`. It never runs upstream code. The report is uploaded as an Actions artifact.
2. If something changed and the `OPENAI_API_KEY` secret is set, a coding agent ports the change to Rust in a sandbox with no write access.
3. A clean job validates the patch (only `src/`, `tests/`, `proto/`, `Cargo.*`, `Dockerfile` and docs may change; workflows and update tooling are off limits), then runs fmt, Clippy, all tests, a real Xray smoke test and a Docker build.
4. Only if everything passes, it opens a **draft PR**. Nothing is merged or deployed automatically — review it.

Setup: add `OPENAI_API_KEY` under *Settings → Secrets and variables → Actions*, and enable *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*. Without the key you still get the daily drift report. Details: [docs/UPDATES.md](docs/UPDATES.md).

## Develop

```bash
cargo test --locked
python3 -m unittest discover -s scripts/tests
python3 scripts/fetch_xray.py --output /tmp/xray
XRAY_BINARY=/tmp/xray/xray cargo test --locked -- --include-ignored
cargo build --locked && python3 scripts/smoke.py --binary target/debug/remnanode-rust --xray /tmp/xray/xray
```

## License

AGPL-3.0-only, same as upstream Remnawave Node.
