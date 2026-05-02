# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Go is at `/usr/local/go/bin/go` (not in default PATH — use `export PATH=$PATH:/usr/local/go/bin` or the Makefile).

```bash
make build        # go mod tidy + compile → ./lan-radar
make build-dev    # same with -race detector
make run          # build + sudo -E ./lan-radar
make install-cap  # build + setcap cap_net_raw+ep (run once to avoid sudo)
make clean
```

Direct Go commands (with PATH set):
```bash
go build -o lan-radar .
go vet ./...
go test ./...                        # no tests currently exist
GOPROXY=direct go mod tidy           # required — default proxy can't resolve some versions
```

The binary requires root or `cap_net_raw` to open AF_PACKET sockets for ARP. It always listens on `127.0.0.1:7777` and opens Chromium via `--app=` flag as the desktop window. Run with `sudo -E` to preserve `$DISPLAY`/`$XAUTHORITY`; Chromium is launched as the original user via `su $SUDO_USER`.

## Architecture

### Data flow

```
Scanner ──┐
Sniffer ──┼──▶  hub.Events (chan api.Event)  ──▶  Hub.RunBroadcastLoop()  ──▶  WebSocket clients
Probe   ──┘                                              │
                                                   Hub.devices (in-memory map, keyed by IP)
                                                   Hub.logger → data/sessions/YYYY-MM-DD.jsonl
```

`Scanner`, `Sniffer`, and `Probe` are decoupled from `Hub` through `hub.Events chan api.Event`. All three write events; the hub reads them, updates its device map, calls the session logger, and fans out to all connected WebSocket clients.

### Backend packages

**`internal/api`** — HTTP + WebSocket server.
- `Hub` owns the device map and broadcast loop. Serves embedded frontend at `/`, WebSocket at `/ws`, REST at `/api/devices`, `/api/mitm/on`, `/api/mitm/off`, `/api/export`.
- `EventLogger` interface: `Log(ev Event)` — only logs `device_found`, `device_lost`, `alert`, `mitm_status`.
- `MITMController` interface wired to `mitmWrapper` in `main.go`.

**`internal/scanner`** — Network discovery.
- `scanner.go` — orchestrator: ARP + mDNS in parallel, marks devices seen/lost, async `enrich()` per new device, `pingLoop()` pings all active hosts every 10s for latency history, ARP spoof detection (alerts on MAC change for known IP).
- `arp.go` — sends ARP to every IPv4 in subnet via `mdlayher/arp` (AF_PACKET, no libpcap).
- `ping.go` — wraps system `ping`; parses TTL for OS guess + RTT (ms) for latency history.
- `portscan.go` — concurrent TCP connect scan ~30 common ports, semaphore 50 goroutines, banner grabbing.
- `mdns.go` — multicast mDNS query + `net.LookupAddr` fallback.

**`internal/sniffer`** — Packet capture and analysis.
- Raw `syscall.AF_PACKET SOCK_RAW ETH_P_ALL` bound to interface index (no libpcap).
- DNS: parses UDP port 53 via `miekg/dns`.
- HTTPS: extracts TLS SNI from ClientHello (extension type 0x0000).
- HTTP: reads `Host:` header from TCP payload.
- Bandwidth: sliding 1-second window per IP (in/out), emits `EventBandwidth` every second.
- Passive OS fingerprinting: guesses OS from TCP window size + TTL, emits `EventPassiveOS` (deduplicated per IP).
- Port scan detection: tracks SYN-only packets to own IPs; alerts if >10 unique dst ports from same src within 5s.
- Threat check: calls `internal/threat` on domain names.
- Async geo lookup via `internal/geo` for external IPs.

**`internal/mitm`** — ARP poisoning.
- `StartMITM()`: resolves gateway MAC via ARP, enables `/proc/sys/net/ipv4/ip_forward`, starts 2s poison loop.
- `StopMITM()`: closes loop, sends correct ARP replies to all targets, disables IP forwarding.

**`internal/probe`** — WiFi monitor mode.
- Adds `mon0` via `iw dev {iface} interface add mon0 type monitor`.
- Parses 802.11 probe requests (type=0/subtype=4), extracts source MAC + SSID IE.
- Gracefully skips if `iw` fails (wired-only systems).

**`internal/geo`** — `Lookup(ip) Info` using ip-api.com, 24h memory cache, skips private IPs, generates emoji flag.

**`internal/threat`** — Static bad-domain/IP map (~40 entries). `Check(indicator) (bool, Hit)`.

**`internal/oui`** — Static MAC vendor map (~600 prefixes). `Lookup(mac string) string`.

**`internal/store`** — Persists to `data/store.json`. `DeviceMeta` with Country/Code/Timeline. Auto-saves every 30s.

**`internal/logger`** — Daily JSONL log to `data/sessions/YYYY-MM-DD.jsonl`. Rotates at midnight.

### Frontend (`frontend/`, embedded into binary)

Single-page Canvas app — no build step, no dependencies. All logic in `radar.js`.

**Key globals:** `devices Map<ip,Device>`, `nodes Map<ip,{x,y,vx,vy,...}>`, `bwHistory[]` (60-sample ring buffer).

**Physics:** O(n²) repulsion, spring-to-gateway, vendor clustering (same OUI prefix = weak attraction), center gravity, DAMPING=0.85. User-pinned nodes (right-click) are fixed.

**Rendering loop:** background → grid → sonar sweep → edges (heatmap) → packet dots → nodes (bandwidth rings, threat glow) → labels → BW chart (bottom-right).

**UI components:** dossier panel (latency sparkline, ports, timeline, geo flag, bandwidth), activity feed (filterable, threat rows), filter bar (ALL/ACTIVE/PORTS/THREAT + vendor input), toasts, toolbar (MITM + Export).

### Event types (`internal/api/types.go`)

| Constant | Wire value | Payload |
|---|---|---|
| `EventDeviceFound/Updated/Lost` | `device_found/updated/lost` | `device` |
| `EventFullState` | `full_state` | `devices`, `traffics`, `mitm_on` |
| `EventTraffic` | `traffic` | `traffic` |
| `EventBandwidth` | `bandwidth` | `bandwidth []BandwidthStat` |
| `EventAlert` | `alert` | `alert` |
| `EventMITMStatus` | `mitm_status` | `mitm_on` |
| `EventPassiveOS` | `passive_os` | `os_hints []OSHint` |
| `EventProbeDevice` | `probe_device` | `alert` |
| `EventScanStart/End` | `scan_start/end` | — |

### Scan cycle

Every 15s: ARP scan (3s) + mDNS (2s) in parallel. New devices: async `enrich()` — ping (2s) + port scan (50 concurrent goroutines). Every 10s: `pingLoop()` re-pings all active devices, appends RTT to `Device.PingHistory` (capped at 20 entries).

### Data persistence

```
data/
  store.json                 # geo, timelines — saved every 30s
  sessions/YYYY-MM-DD.jsonl  # daily event log
```
