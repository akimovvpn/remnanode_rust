# Client split DNS

An application's DNS packet sent through a SOCKS inbound keeps that inbound's tag
(for example, `socks`). A built-in DNS tag such as `dns_in` labels the resolver's
own upstream requests. Rules matching only `dns_in` therefore do not intercept an
application's UDP query to `77.88.8.8:53`; it follows the ordinary outbound route.

Patch the **client's actual Xray JSON**, exported from its application:

```sh
python3 scripts/fix_client_dns.py client.json client-dns-fixed.json
```

The script adds a first routing rule for TCP/UDP port 53 from the client's actual
tagged SOCKS/HTTP inbounds to a DNS outbound. It appends that outbound, leaving the
default outbound and all existing routing rules in order. A conflicting
`dns-out` tag is preserved and a free suffix is chosen. Reapplying the script
does not add duplicates. Missing `proxy` outbounds are allowed because a
Remnawave template may inject them later.

It removes only `localhost` entries from `dns.servers`, avoiding system resolver
fallback. It keeps the domain-scoped Yandex DoH server, RU/geosite domain rules,
`skipFallback: true`, global Google/Cloudflare servers, TCP fallbacks, hosts,
credentials and other settings. Resolver selection and fallback among those
remaining servers follow the existing DNS configuration.

Input and existing output files are never overwritten. The new file is published
atomically with private file permissions and contains the original credentials;
keep it private. The script accepts strict JSON, rejects duplicate keys and
checks the fields it needs. It does not validate every Xray option.

Before importing the output, validate the **fully assembled** config with the
client's own Xray executable, including its normal geosite/geoip asset directory:

```sh
xray run -test -config client-dns-fixed.json
```

This behavior was verified with Go Xray **26.11.9**. With empty DNS-outbound
settings, that version resolves A/AAAA queries through the built-in DNS module
and returns empty successful replies for other query types. Older client cores
may differ; the client's version and exported JSON are needed to check them.

The interception applies to DNS traffic that reaches these proxy inbounds on
port 53. Native application DNS outside SOCKS, application-managed DoH/DoT,
and OS DNS require the application's own DNS/TUN routing settings. This script
does not change OS settings or implement a DNS engine in the Rust node.

## Reproducible local check

```sh
XRAY_BINARY=/path/to/verified/xray python3 -m unittest scripts.tests.test_client_dns
```

The integration test uses the pinned Go core and two loopback TCP DNS servers
with different sentinel answers. With a blackhole default outbound, an original
SOCKS UDP query to `77.88.8.8:53` reaches neither resolver. After patching,
`sample.ru` reaches only the RU resolver and `sample.com` only the global one.
It also checks TCP DNS interception and the default non-IP-query response.
No external DNS server is contacted. Without `XRAY_BINARY`, only the JSON/CLI
tests run and the Go integration test is explicitly skipped.

Upstream reference: Xray 26.11.9's
[DNS outbound configuration](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/dns_proxy.go)
and [DNS query handling](https://github.com/XTLS/Xray-core/blob/v26.11.9/proxy/dns/dns.go).
