# Mihomo and older REALITY clients

The Rust core accepts authenticated classical X25519 REALITY clients by default, alongside modern hybrid clients. The user explicitly approved this compatibility exception on 2026-11-14. It applies to rcore's REALITY inbounds, including RAW + Vision and XHTTP; the bundled Go binary is unchanged.

## Why a newer Xray server breaks working clients

There are two separate changes:

1. Xray v26.7.11 introduced a default minimum REALITY client version. Mihomo still advertises `1.8.2`. Explicit server version restrictions can reject it independently of any key exchange issue. The [pinned v26.11.9 server parser](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/transport_security.go#L99-L116) leaves the minimum unset when omitted.
2. [REALITY commit `8cdf7bf9c7f0`](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f0), included in Xray v26.9.9 and later, requires an X25519-MLKEM768 ClientHello key share before an optional standalone X25519 share. Classical-only clients are sent to the camouflage target even if their REALITY credentials are correct. `minClientVer: "0.0.0"` cannot change that check.

The [Remnawave forum report](https://f.docs.rw/t/topic/852) describes the same break moving from Node 3.4.3 to 3.4.4. Apps can bundle different Mihomo/uTLS versions, so the same `firefox` fingerprint name does not guarantee the same ClientHello. [Xray issue #7259](https://github.com/XTLS/Xray-core/issues/7259) also documents failing older fingerprints.

Mihomo [v1.19.34's client source](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/component/tls/reality.go) removes hybrid key shares unless `reality-opts.support-x25519mlkem768` is enabled. Enabling it only retains a hybrid share if the selected fingerprint offers one. [Mihomo's TLS documentation](https://wiki.metacubex.one/en/config/proxies/tls/#reality-opts) explicitly disclaims compatibility with newer Xray defaults.

## The Rust exception

rcore restores the [historical Go REALITY selector](https://github.com/XTLS/REALITY/blob/9234c772ba8f/tls.go): use the first valid-length standalone X25519 share; otherwise use the X25519 component of the first valid-length hybrid share. Standalone authentication-key precedence matters when the two keys differ. This also restores historical handling of duplicate shares and either ordering. A failed authentication does not retry another key.

The authenticated ClientHello, contributory key check, short ID, SNI, TLS 1.3, configured client-version/time bounds and VLESS UUID are still required. Invalid authentication still goes to the real target. A network observer cannot strip a hybrid share from an authenticated hello: modifying the hello invalidates its authentication tag.

This admits older browser fingerprints and permits classical-only TLS when selected by the target. It does not provide post-quantum key exchange for classical-only clients. Modern clients can still negotiate hybrid TLS when both they and the target support it.

## Deployment and limits

Select the Rust binary in the node's existing Compose environment:

```yaml
environment:
  XRAY_BINARY: /usr/local/bin/rcore
```

Pull the updated image, recreate the container and restart the node from the panel. No extra compatibility setting is needed. If the inbound explicitly sets a minimum newer than `1.8.2` or a maximum below it, change that restriction deliberately in the panel profile; rcore does not bypass it. An omitted minimum or `"0.0.0"` permits Mihomo's advertised version.

Client and server must still agree on protocol, transport, flow, SNI, public key and short ID. The camouflage target must support TLS 1.3 and the client's key exchange; classical-only clients need a target accepting X25519. This does not add unported protocols, fix client subscription generation or bypass a network blocking a fingerprint. HTTP/3 and XHTTP `h2Params` remain unsupported. No single server change can guarantee every client app/version/configuration works.

## Reproducing the checks on Linux

```bash
python3 scripts/fetch_mihomo.py --output /tmp/mihomo
python3 scripts/fetch_xray.py --output /tmp/xray
MIHOMO_BINARY=/tmp/mihomo/mihomo XRAY_BINARY=/tmp/xray/xray \
  cargo test --locked -p rcore --test vision_interop
```

The client download pins official release v1.19.34 and verifies the published SHA256. Tests exercise classical-only Chrome, Firefox, Edge and iOS fingerprints, explicit modern Chrome hybrid support, RAW + Vision, TCP, inner TLS 1.2/1.3 transfers, XUDP and all three XHTTP modes. Existing Go interop and unauthenticated visitor tests remain part of the workspace suite.
