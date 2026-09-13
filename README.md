# OpenFlux

**English** | [Русский](README.ru.md)

Network stack research tool. TCP tunnel with pluggable transports.


# Disclaimer

The author of OpenFlux **does not encourage** the use of this project to bypass restrictions or violate the rules of any platform, and **is not responsible** for the final scenarios of how users apply this tool in real life or on the Internet. Any specific technical features of the application are nothing more than an **architectural coincidence**, created **without any intent**.

The project is **entirely non-commercial**, contains **no paid features, hidden subscriptions, or commercial benefit**.

The author **is not responsible** for forks, modifications, or derivative versions of OpenFlux created by third parties. Any changes added to a fork are the responsibility of its author.

The author **is not responsible** for:

- Any use of OpenFlux by third parties
- Consequences caused by the use of forks and modifications
- Damage resulting from derivative versions
- Violations committed using forks

The original code is provided **as is**, **without any warranties**.

## Clients

| Platform | Download | Notes |
|----------|----------|-------|
| **Android** | [OpenFluxAndroid releases](https://github.com/p1neappleXpress/OpenFluxAndroid) | Standalone APK |
| **iOS** | [TestFlight beta](https://testflight.apple.com/join/BwnAcdus) | System-wide VPN via Network Extension |

> **iOS app** built by [@saharev1](https://github.com/saharev1) — full iOS client, TestFlight pipeline, system VPN support, DNS-over-TLS, and many stability fixes. HUGE thanks! 🙏
>
> **Android app** — [p1neappleXpress/OpenFluxAndroid](https://github.com/p1neappleXpress/OpenFluxAndroid).

## Overview
```
Client (SOCKS5) --> Transport --> Exit Node --> Internet
```

## Requirements
1. Golang v. 1.26.3+ - is required for building desktop client / exit node binary (universal-bypass-tool);
2. Android Native Development Kit (NDK) v.27.0.12077973+ - is required for building Android client binary;
3. XCode v. 26.6+ - is required for building iOS client binary;
4. Linux VPS / VDS exit node.

## Overview

TCP packets are sent via Transport. Currently, there are three transports available:
1. Yandex (`--transport yandex`) - sends packets via Yandex Docs cursor messages, using the **legacy** document editor;
2. Volga (`--transport vyandex`) - the same idea on the **new** editor, relaying packets through the Volga session API. Pick this one for documents that open in the new editor. Both `disk.yandex.ru` and `disk.yandex.com` links work; the session is bound to whichever host the document belongs to;
3. Max (`--transport oneme`) - sends packets via WebRTC DataChannel
    WARNING:
   - **Do not use** your primary or important MAX account.
   - **Do not use** an account whose deletion or loss of access would be critical.   
   - Usage via an **external VPS** may lead to **account restrictions**.
   - The **restriction may persist** after stopping OpenFlux.
   - MAX transport should be considered **experimental** until the blocking mechanism is understood. 

Client side runs a SOCKS5 proxy, exit node decapsulates and forwards packets to destination point.

## Structure

```
OpenFlux/
├── main.go                     # CLI entry (client / exit-node)
├── export_ios.go               # cgo bridge for the iOS static library (build tag: ios)
├── transport/
│   ├── transport.go            # Transport interface
│   ├── compressor.go           # Compression wrapper
│   ├── yandex/                 # Yandex Docs backend
│   └── oneme/                  # MAX Messenger backend
├── tunnel/
│   ├── tunnel.go               # TCP tunnel core
│   ├── endpoint.go             # Virtual NIC
│   └── rawsocket_{linux,darwin,windows}.go  # Raw socket (exit node), per-OS
├── socks5/                     # SOCKS5 server
├── network/                    # Checksums, packet parsing
├── utils/                      # Logging
├── ios-app/                    # SwiftUI iOS client (XcodeGen), links liboflux.a
├── build_ios.sh                # Build the iOS static library (liboflux.a)
├── build_ios_app.sh            # Build + archive + export the iOS app IPA
└── build_android.sh            # Build the Android client binary
```

## Build (desktop client / exit-node binary)

```bash
go mod tidy
go build -o universal-bypass-tool .
```

## Build for Android (client binary)
```bash
export ANDROID_NDK_HOME=<your Android NDK path>
./build_android.sh
```

## Build for iOS (client binary)
```bash
export XCODE_PATH="<your Xcode.app path>" # optional, defaults to /Applications/Xcode.app
./build_ios.sh
```

## Usage

### 1. Setting up exit node
1. You must have root access on exit node machine;
2. Only legacy Yandex document editor is supported (you can toggle this setting from the interface).

The exit node's TCP connections live in a userspace stack (gvisor), so the
kernel has no socket for them and would send an RST on every reply, tearing
the tunnel down. That RST must be suppressed — but do it **scoped**, not
host-wide. A blanket `-j DROP` on all outbound RSTs makes every closed port
answer with silence (scanners see `filtered` instead of `closed`) and stops
the host from resetting unrelated connections.

Recommended (scoped to a dedicated egress IP):
```bash
# give the box a second/alias IP for the tunnel, e.g. 203.0.113.10
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 203.0.113.10 -j DROP
sudo ./universal-bypass-tool --exit-node --local-ip 203.0.113.10 \
    --url "YOUR_YANDEX_DOC_URL" --debug
```
Even cleaner: run the exit node in its own network namespace / container so the
rule never touches the host's main services. Note that `-m owner --uid-owner`
does **not** work here — the tunnel-breaking RSTs are generated by the kernel
with no owning socket, so the owner match never fires.

Host-wide fallback (only on a single-purpose box, understanding the trade-off):
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./universal-bypass-tool --exit-node --url "YOUR_YANDEX_DOC_URL" --debug
```

### 1. Setting up desktop client:

Setup commands for desktop client:
```bash
./universal-bypass-tool --client --url "YOUR_YANDEX_DOC_URL" --socks5 :1080 --debug
```

Then set up SOCKS5 proxy in your browser at localhost:1080.

## Encryption

> **Compatible with older peers.** The keep-alive now travels through the same
> compression and encryption as real traffic instead of being a constant
> plaintext marker, but real packets are forwarded byte for byte. A client and
> an exit node on different builds still talk to each other, so you can update
> one side at a time. Turning encryption *on*, of course, requires both.

The transport itself carries your packets as base64 inside document messages.
The hops to the provider are TLS, so your ISP and the local network see
nothing - but TLS terminates at the provider, and the document is the
rendezvous point. Without the layer below, **the document provider sees every
tunnelled packet in plaintext**, and anyone holding the document URL can both
read the tunnel and inject packets into it.

Turn on end-to-end AES-256-GCM by putting a shared secret in the URL:

```
ydocs://DOC_URL#SHARED_SECRET
```

Give **both peers the same link**. Everything up to the final `#` is the
document URL (`https://` is implied); everything after it is the secret, which
never leaves the machine - it is only an input to the key derivation.

```bash
# exit node
sudo ./universal-bypass-tool --exit-node \
    --url "ydocs://docs.yandex.ru/docs/view?id=YOUR_DOC#a-long-shared-secret" --debug

# client
./universal-bypass-tool --client \
    --url "ydocs://docs.yandex.ru/docs/view?id=YOUR_DOC#a-long-shared-secret" \
    --socks5 :1080 --debug
```

Both sides log `Transport encryption: AES-256-GCM enabled` on startup. The
iOS and Android clients accept the same link in their URL field.

Details:

- The secret must be at least 16 characters. Generate one with
  `openssl rand -base64 32`.
- Each direction gets its own derived key, every packet carries a random
  nonce, and replays are rejected within a bounded window.
- A plain `https://` URL keeps the old, unencrypted behaviour unchanged.
- To keep the secret out of shell history and `ps` output, pass a plain URL
  plus `--encryption-key-file /path/to/secret`. The two forms interoperate:
  a peer using the key file and a peer using a `ydocs://` link derive the same
  keys as long as the document URL and the secret match.

## Running several exit nodes on one VPS

One exit node per document link. They coexist on a single IP, but a few
details decide whether that works well or badly.

Give each link its own systemd instance, with its own environment file:

```ini
# /etc/systemd/system/openflux-exit@.service
[Unit]
Description=OpenFlux exit node (%i)
Wants=network-online.target
After=network-online.target openflux-rst-drop.service
Requires=openflux-rst-drop.service

[Service]
Type=simple
EnvironmentFile=/etc/openflux/instances/%i.env
ExecStart=/usr/local/bin/openflux --exit-node --transport ${TRANSPORT} --url ${YANDEX_DOC_URL} $EXTRA_ARGS
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
# /etc/openflux/instances/phone.env
TRANSPORT=vyandex
YANDEX_DOC_URL=https://disk.yandex.com/i/YOUR_DOC
EXTRA_ARGS=
```

```bash
sudo systemctl enable --now openflux-exit@phone.service
```

Taking `TRANSPORT` from the instance file rather than the unit lets different
links use different transports on the same box.

### Watch the raw socket drop counter

Each exit node opens a raw TCP socket, and **every** raw TCP socket on the host
receives a copy of **every** TCP packet - the other instances' tunnels, SSH,
everything else. Each instance filters out what is not its own, but it has to
read the packet to do that. If an instance cannot drain its socket fast enough,
the kernel discards the overflow silently: no error, no log, just unexplained
loss inside the tunnel.

That counter is the first thing to check when several links "work badly":

```bash
grep ":0006" /proc/net/raw | awk '{print "drops=" $NF}'
```

One line per exit node, and the last column is a cumulative drop count. It
should stay at or near zero. If it climbs, the exit nodes are not keeping up.

Two changes keep it there:

- The egress IP is resolved once instead of per packet. It used to be
  rediscovered for every packet in both directions, and discovery opens and
  closes a UDP socket, so the cost scaled with traffic and with the number of
  instances.
- The raw receive buffer is raised to 8MB, well above the 208KB default, to
  absorb bursts.

If drops still climb, the box is simply out of headroom: run fewer instances
per host, or give each one a dedicated egress IP with `--local-ip` so the
kernel hands it less to sift through.

### Sizing the relay pool

The `vyandex` relay pool is sized from the CPU count (128 workers per core,
capped at 1024). It used to be a flat 2000 workers with room for 2000 idle
TLS connections per instance, which a tunnel cannot use - batches carry up to
20 packets, so even a busy link keeps only tens of requests in flight - and on
a one-core VPS running three exit nodes it was thousands of goroutines
competing for a single core.

Override it if your box wants something else:

```sh
# /etc/openflux/instances/phone.env
OPENFLUX_RELAY_WORKERS=256
```

## Throughput

Relaying through a document service is a high-latency path: about 190ms per
round trip on a test VPS, against 45ms direct. Latency that high is what
decides throughput, because a TCP connection can only have one window of data
in flight per round trip.

Two settings followed from that, both in `tunnel/tunnel.go`:

- **CUBIC instead of Reno.** gvisor's `tcp.NewProtocol` still defaults to Reno,
  which grows its window linearly and gives up half of it on every loss. Over
  a 190ms path that recovers far too slowly. `tcp.NewProtocolCUBIC` is the
  same stack with a congestion control designed for exactly this.
- **Windows sized for the round trip.** The receive and send buffers cap the
  window, and the window over the round trip caps the rate. The old 256KB
  default limited a single connection to roughly 1.3MB/s however much
  bandwidth was actually available. They are limits, not reservations, so
  idle connections cost nothing.

Measured on the test VPS, downloading through one exit node:

| | before | after |
|---|---|---|
| single 8MB stream | 66.4s (120 KB/s) | **6.6s (1.22 MB/s)** |
| 16MB across 4 streams | did not finish in 150s | **12s** |

A third setting is the exit node's garbage collector. It used to be pinned at
`GOGC=20`, which on a single core spends real forwarding time collecting after
every batch's JSON, base64 and TLS allocations. Measured over the same 8MB
download:

| GOGC | throughput | resident |
|---|---|---|
| 20 (old) | 1.10 / 0.98 MB/s | 46MB |
| 100 (now the default) | **1.23 / 1.11 MB/s** | 72MB |
| 400 | 1.09 / 1.08 MB/s | 211MB |

More is not better - a bigger heap costs more than it saves. `GOGC` and
`GOMEMLIMIT` from the environment take precedence, and `GOMEMLIMIT` is the
better lever on a genuinely memory-starved box because it caps the heap
without paying for a collection on every small increment.

Round-trip time is unchanged at ~0.76s for a small request. That is the relay
itself and no local setting will move it, so the tunnel will always feel
slower than the link it runs over even when bulk transfers are fast.

The iOS Network Extension deliberately does not get these buffers: it runs
under a ~50MB memory cap and forwards raw L3 packets with no stack of its own.

## Flags

| Flag          | Default             | Description                |
|---------------|---------------------|----------------------------|
| `--client`    |                     | Run as client              |
| `--exit-node` |                     | Run as exit node           |
| `--socks5`    | `:1080`             | SOCKS5 listen address      |
| `--url`       | `https://localhost` | Document URL, or a `ydocs://DOC_URL#SECRET` link |
| `--maxToken`  | ``                  | Auth token (Max)           |
| `--maxUid`    | ``                  | User ID (Max)              |
| `--debug`     | `false`             | Enable verbose logging     |
| `--transport` | `yandex`            | Select transport backend   |
| `--encryption-key-file` | ``        | Read the shared secret from a file instead of the link |

## Implementing custom transports

You are free to implement the `Transport` interface from `transport/transport.go` and register your custom transport in main.go switch block.

## License

This project is licensed under the **GNU General Public License v3.0 or later**.
See [LICENSE](LICENSE) for the full text.

Third-party licenses are listed in [NOTICE](NOTICE).

## Disclaimer

Educational use only. Test on your own machines and networks.

## Support the project

**USDT · TRC20**

```
TXyTj5DqJNcQpd2yWwdVuXdabvQibXgLKC
```
