# Local Linux release benchmark — 2026-11-13

Rust uses substantially less resident memory in these single-connection fixtures.
After bypassing Vision framing when a direction switches to direct copy,
Rust Vision median server CPU fell from **0.48 to 0.19 CPU s/GiB** (about 60%).
The corresponding Go median is 0.20 CPU s/GiB. That 10 ms difference is one
accounting tick: the measurements **do not establish a general CPU advantage
over Go**. Plain VLESS also remains comparable. These are local release-build
results, not a claim about a published image.

## Scope and method

`scripts/bench_core.py` uses the same pinned Go Xray client for both servers. It
creates disposable loopback configurations and verifies all application payload
bytes at both ends. The server configurations are identical between Rust and Go;
only the server executable changes. Cases are plain TCP VLESS and RAW VLESS over
REALITY with `xtls-rprx-vision`, carrying an independently verified TLS 1.3
connection to a local TLS application. The application trusts only the generated
local test certificate. No private user configuration or external traffic target
is used.

Each measurement starts a fresh server and Go client. It excludes connection
setup, REALITY target calibration, and a 4 MiB upload + 4 MiB download warmup on
the same connection. The fixture acknowledges the initial small request before
bulk upload so the Go client can observe a complete TLS application record.
For every Vision measurement, the harness requires Go client debug log evidence
of **command 2 in both directions** before accepting the result. Plain VLESS
carries plaintext application data; Vision carries encrypted TLS records.

Each row transfers **536,870,912 application bytes up and 536,870,912 down**, in
that order. Thus the CPU denominator is **1 GiB of total application traffic**, not
1 GiB in each direction. Test framing, TLS/REALITY overhead and warmup bytes are
excluded from the denominator. There are three paired rounds per case; the order
is Rust/Go, Go/Rust, Rust/Go. Server log level is `error` for both implementations;
client log level is `debug` for direct-copy evidence.

CPU is the difference in Linux `/proc/PID/stat` `utime + stime` for the **server
process only**, divided by `SC_CLK_TCK` (100 here). Application, TLS endpoint,
Go client and sampler CPU are excluded. `elapsed` is wall time for application
transfer and includes their contribution to throughput. It is not a server-only
throughput limit. RSS is read from server `/proc/PID/status`: `warm` and `steady`
are medians of twenty 10 ms samples before and after the measured transfer;
`peak` is the largest RSS sampled during transfer at 10 ms intervals, including
its endpoints. The JSON also records kernel lifetime `VmHWM`, which can include
startup peaks and is distinct from the post-warmup sampled peak below.

## Environment and binary identity

- Source base: `75ab649f8bbbcb7b93462dbbd6cdc372878b1335`; concurrent XHTTP-only
  changes are outside both measured paths. The binary hash identifies the exact
  measured artifact; later source changes are not represented by these results.
- Rust: `cargo build --release --locked -p rcore`, default Cargo release profile;
  `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1,
  `aarch64-unknown-linux-gnu`. No native-CPU flags or PGO were added.
- Rust binary SHA-256:
  `7a4a7711f2a604897d0850025ed75069caad296736e075038eac13942694bbbb`.
- Go: pinned Xray `26.11.9`, commit `676eaf6`, `go1.27.3 linux/arm64`, provided
  release binary `/tmp/remnanode-xray-linux`.
- Go binary SHA-256:
  `c2d1e66a130556d32089adcf38202fcb6f9027e41fb456cc2cda9a5fabdc093a`.
- Docker Linux VM: `6.12.76-linuxkit`, `aarch64`, Apple CPU, eight visible CPUs;
  container `cpu.max = max 100000`, `memory.max = max`. Shared developer machine;
  no CPU affinity, dedicated host or frequency control.
- Harness: Python 3.13.5, OpenSSL 3.5.7. Rust build image:
  `remnanode-rust:reality-build`, image SHA-256
  `a0d5175448ac01ea992e00e080e657ee44e5dbc7a3412453d2382d118322a74f`.

## Baseline results

CPU seconds equal CPU seconds/GiB for these 1 GiB rows. RSS values are KiB.

| Case | Round | Server | CPU s/GiB | Elapsed s | Warm RSS | Steady RSS | Sampled peak RSS |
|---|---:|---|---:|---:|---:|---:|---:|
| Plain VLESS | 1 | Rust | 0.34 | 1.041447 | 7132 | 7132 | 7132 |
| Plain VLESS | 1 | Go | 0.32 | 0.895936 | 16892 | 22496 | 22496 |
| Plain VLESS | 2 | Go | 0.33 | 0.868155 | 15036 | 20048 | 20192 |
| Plain VLESS | 2 | Rust | 0.30 | 0.819070 | 7128 | 7128 | 7128 |
| Plain VLESS | 3 | Rust | 0.29 | 0.813227 | 7136 | 7136 | 7136 |
| Plain VLESS | 3 | Go | 0.26 | 0.806660 | 17252 | 20536 | 20536 |
| Vision + TLS 1.3 | 1 | Rust | 0.47 | 1.656099 | 8328 | 8336 | 8336 |
| Vision + TLS 1.3 | 1 | Go | 0.19 | 1.647862 | 24540 | 24724 | 24724 |
| Vision + TLS 1.3 | 2 | Go | 0.21 | 1.508988 | 25988 | 26300 | 26728 |
| Vision + TLS 1.3 | 2 | Rust | 0.48 | 1.569251 | 8336 | 8336 | 8336 |
| Vision + TLS 1.3 | 3 | Rust | 0.48 | 1.660375 | 8240 | 8248 | 8248 |
| Vision + TLS 1.3 | 3 | Go | 0.20 | 1.654556 | 27472 | 28236 | 28236 |

Median steady RSS is 7132 vs 20536 KiB for plain VLESS (about 65% lower for Rust),
and 8336 vs 26300 KiB for Vision (about 68% lower). Median CPU s/GiB is 0.30 vs
0.32 for plain VLESS and 0.48 vs 0.20 for Vision. The 10 ms process CPU tick and
shared machine variation make the small plain-VLESS difference inconclusive.

Raw JSON, generated configs, local certificates and debug logs for this run are
in `/tmp/remnanode-bench-release-20261113/` on the measurement machine. Those
artifacts are temporary; the table above preserves all twelve accepted rows.
A 1 MiB smoke run also completed all four server/case combinations and their
integrity/direct-copy assertions; its CPU values were too quantized to report.

## After direct-copy passthrough

The second run uses the same workload, sampling logic, environment, traffic
sizes and Go binary. Between runs the harness only gained binary hashes and
Rust version metadata and lost an unused import; traffic and measurement code
did not change. The baseline hashes above were captured with `sha256sum` before
its measurement; its older JSON metadata does not contain them. The second
run records both binary hashes directly in its JSON.
After transition data drains, Rust's Vision I/O now directly delegates reads and
writes to its inner stream, matching Go's switch to a raw reader/writer. This
avoids the temporary read buffer, decoder copying and encoder allocation after
the framing phase. The wrapper uses the existing TLS direct-control flags.
XHTTP-only limit removals are present in the source but outside these paths.
Other test workloads were paused for all twelve measurements in this run.

The exact frozen-source build completed successfully with
`cargo build --release --locked -p rcore`. Its Rust binary SHA-256 is
`370769f648400739a4bdb04123ec2648cc911e5a741d2ace9e5b59e51f894b2f`.
The source base is the same commit as above. SHA-256 of
`git diff --binary -- rcore/src/vision.rs rcore/src/tls13.rs rcore/src/xhttp.rs`
at build time is
`e7f1d910ff7f1eb7072dfa586acf9afe3038fa216400ff1d034cb5cb058f71d9`;
it was unchanged immediately before measurement. The corresponding patch is
`/tmp/remnanode-direct-benchmark-source.patch`. Both exact Rust binaries remain
in the retained benchmark container as `/tmp/rcore-bench-release` (baseline) and
`/tmp/rcore-direct-release` (after).

Again, every row is 512 MiB upload + 512 MiB download = **1 GiB total**.

| Case | Round | Server | CPU s/GiB | Elapsed s | Warm RSS | Steady RSS | Sampled peak RSS |
|---|---:|---|---:|---:|---:|---:|---:|
| Plain VLESS | 1 | Rust | 0.30 | 0.819977 | 7196 | 7196 | 7196 |
| Plain VLESS | 1 | Go | 0.26 | 0.819078 | 17020 | 20024 | 20348 |
| Plain VLESS | 2 | Go | 0.29 | 0.811162 | 17144 | 22388 | 22388 |
| Plain VLESS | 2 | Rust | 0.28 | 0.805353 | 7196 | 7196 | 7196 |
| Plain VLESS | 3 | Rust | 0.29 | 0.802979 | 7200 | 7200 | 7200 |
| Plain VLESS | 3 | Go | 0.28 | 0.826335 | 17132 | 21544 | 21544 |
| Vision + TLS 1.3 | 1 | Rust | 0.19 | 1.640575 | 8280 | 8280 | 8280 |
| Vision + TLS 1.3 | 1 | Go | 0.20 | 1.657590 | 25832 | 26828 | 26944 |
| Vision + TLS 1.3 | 2 | Go | 0.20 | 1.483809 | 25772 | 26332 | 26848 |
| Vision + TLS 1.3 | 2 | Rust | 0.19 | 1.454705 | 8216 | 8220 | 8220 |
| Vision + TLS 1.3 | 3 | Rust | 0.20 | 1.560621 | 8272 | 8272 | 8272 |
| Vision + TLS 1.3 | 3 | Go | 0.22 | 1.695339 | 25904 | 26108 | 26108 |

After-change median steady RSS is 7196 vs 21544 KiB for plain VLESS (about 67%
lower for Rust), and 8272 vs 26332 KiB for Vision (about 69% lower). Median CPU
s/GiB is 0.29 vs 0.28 for plain VLESS and 0.19 vs 0.20 for Vision. Both Go
comparisons are within the range where CPU accounting resolution and machine
variation matter; neither establishes a CPU win. The previous 2.4× Vision CPU
regression is absent in this fixture, while its memory advantage remains.

All twelve after-change transfers passed payload integrity checks and all six
Vision transfers confirmed both direct-copy directions. Raw JSON, generated
configs, certificates and client logs are retained in
`/tmp/remnanode-bench-direct-20261113/` separately from the baseline artifacts.

## Reproduction

Build the Rust executable in Linux, not a macOS debug binary. Create the local
toolchain image with `docker build --target build -t remnanode-rust:reality-build .`
if it is not already available. The commands below use its cached
target directory; provide the pinned Linux Go binary at the shown path. Python
is installed only in the disposable benchmark container, not added to either
core's runtime dependencies.

```sh
docker run --rm \
  -v "$PWD:/src:ro" \
  -v /tmp/remnanode-reality-linux-target:/tmp/rcore-linux-target \
  -w /src -e CARGO_TARGET_DIR=/tmp/rcore-linux-target \
  remnanode-rust:reality-build cargo build --release --locked -p rcore

docker run --rm \
  -v "$PWD:/src:ro" \
  -v /tmp/remnanode-reality-linux-target:/build:ro \
  -v /tmp/remnanode-xray-linux:/opt/xray:ro \
  -v /tmp:/results \
  remnanode-rust:reality-build sh -c '
    apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 openssl &&
    cp /build/release/rcore /tmp/rcore-release &&
    python3 /src/scripts/bench_core.py \
      --rust /tmp/rcore-release --go /opt/xray \
      --rounds 3 --mib 512 --output /results/rcore-benchmark-new
  '
```

The output directory must not already exist. To smoke-check the fixture first,
use a different output directory and `--rounds 1 --mib 1`; use the full payload
for reported CPU measurements. The harness aborts on payload corruption, server
exit, socket timeout or missing Vision direct-copy evidence.

These results do not cover other protocols, startup CPU, connection churn,
concurrent clients, real networks, x86 hardware, production deployments or the
memory cost of the same complete Go feature set. A 10 ms RSS sampler can miss
short peaks. Lower RSS here does not demonstrate completion of the full port.
