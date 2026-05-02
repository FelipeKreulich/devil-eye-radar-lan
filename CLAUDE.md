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

Direct Go commands:
```bash
go build -o lan-radar .
go vet ./...
GOPROXY=direct go mod tidy   # required — default proxy can't resolve some versions
```

The binary requires root or `cap_net_raw`. Listens on `127.0.0.1:7777`. Opens Chromium via `--app=` as the original user (`su $SUDO_USER`) when run with `sudo -E`.

## Architecture

### Data flow

```
Scanner ──┐
Sniffer ──┼──▶  hub.Events (chan api.Event)  ──▶  Hub.RunBroadcastLoop()  ──▶  WebSocket clients
Probe   ──┘                                              │
                                                   Hub.devices (map)
                                                   Hub.logger → data/sessions/YYYY-MM-DD.jsonl
```

### Backend packages

**`internal/api`** — HTTP + WebSocket server (`server.go`) + type definitions (`types.go`).
- `Hub` owns device map + broadcast loop. Serves frontend at `/`, WebSocket at `/ws`.
- Interfaces: `MITMController`, `DNSSpoofController`, `EventLogger`.
- REST endpoints: `/api/devices`, `/api/mitm/on|off`, `/api/export`, `/api/sessions`, `/api/sessions/{date}`, `/api/dnsspoof/status|on|off|rules`.
- `sendFullState` on new WebSocket connection: all devices + recent traffic + MITM state.

**`internal/scanner`** — Network discovery.
- `scanner.go`: ARP + mDNS in parallel every 15s. `enrich()` per new device: ping + port scan + CVE matching + TopoLayer assignment. `pingLoop()` re-pings all active hosts every 10s (PingHistory, max 20 entries). ARP spoof detection (MAC change for known IP → danger alert).
- `arp.go`: ARP scan via `mdlayher/arp`.
- `ping.go`: wraps `ping` binary; parses TTL (OS guess) + RTT (ms).
- `portscan.go`: ~30 ports, 50 concurrent goroutines, banner grabbing.
- `mdns.go`: mDNS query; parses PTR/SRV/A records; maps service types to device types (22 entries: `_airplay._tcp` → "Apple TV", etc.).

**`internal/sniffer`** — Raw AF_PACKET packet capture.
- DNS (miekg/dns), HTTPS TLS SNI, HTTP Host parsing.
- Bandwidth: 1s sliding window per IP, `EventBandwidth` every second.
- Passive OS fingerprinting: TCP window + TTL → `EventPassiveOS` (deduplicated).
- Port scan detection: SYN-only packets to own IPs; >10 unique ports/src in 5s → alert.
- Traffic correlation: private↔private pairs flushed as `EventPeerLink` every 10s.
- DHCP rogue detection: DHCP OFFER/ACK from non-gateway → danger alert.
- SSL stripping detection: HTTP access to domain previously seen via HTTPS → `EventSSLStrip`.

**`internal/mitm`** — ARP poisoning via `mdlayher/arp`. 2s poison loop. `restore()` on stop. Manages `/proc/sys/net/ipv4/ip_forward`.

**`internal/dnsspoof`** — DNS interception.
- `Start()`: adds iptables PREROUTING rule redirecting UDP/53 to port 15353 (scoped to LAN interface).
- `listen()` + `handleQuery()`: serves fake A records for matched domains; forwards rest to 8.8.8.8.
- `Stop()`: removes iptables rule.
- Runtime rule management: `AddRule(domain, ip)`, `RemoveRule(domain)`, `Rules()`.

**`internal/cve`** — Static CVE database (21 rules). `Match(port int, banner string) []Entry`. Covers: vsftpd, ProFTPD, OpenSSH, Telnet, Apache, Nginx, Tomcat, SMB/EternalBlue, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB.

**`internal/probe`** — 802.11 monitor mode. `mon0` via `iw`. Parses probe requests (type=0/subtype=4). Gracefully skips if `iw` fails.

**`internal/geo`** — ip-api.com, 24h memory cache, emoji flags, skips private IPs.

**`internal/threat`** — Static bad-domain/IP map (~40 entries). `Check(indicator) (bool, Hit)`.

**`internal/oui`** — MAC vendor map (~600 prefixes). `Lookup(mac string) string`.

**`internal/store`** — `data/store.json`. Country/code/timeline per device. Auto-saves every 30s.

**`internal/logger`** — JSONL log `data/sessions/YYYY-MM-DD.jsonl`. Daily rotation. Logs device_found/lost, alerts, MITM status with IP/MAC/vendor/hostname.

### Frontend (`frontend/`, embedded into binary)

Single-page Canvas app — no build step, no dependencies. All in `radar.js`.

**Key globals:** `devices`, `nodes`, `peerLinks`, `domainCounts`, `bwHistory`, `encCount`, `plainCount`, mode flags (`topoMode`, `heatmapMode`, `statsVisible`, `replayMode`, `dnspoofVisible`).

**Physics (force-directed):** repulsion O(n²), spring-to-gateway, vendor clustering (same OUI = weak attraction), center gravity, DAMPING=0.85. Skipped when `topoMode=true` (fixed concentric rings). User-pinned nodes (right-click) are fixed.

**Rendering loop:**
1. Clear + radial gradient bg
2. Grid rings
3. Sonar sweep
4. `drawHeatmap()` if heatmapMode (additive screen blending, radial gradient per active node)
5. `drawEdges()` — edge thickness/opacity scales with bandwidth
6. `drawPeerLinks()` — dashed cyan lines between correlated peers
7. `drawNodes()` — bandwidth rings, threat glow, vendor labels, topo layers
8. `drawBWChart()` — 60s history (bottom-right canvas)

**Toolbar buttons:** MITM, EXPORT, ⬡ TOPO, ◉ HEAT, ≡ STATS, ⏪ REPLAY, ⚡ SPOOF.

**Panels (floating, toggleable):**
- `#stats-panel` — devices, top domains, busiest hosts, enc%, bytes
- `#replay-panel` — date picker → load JSONL → play/stop/speed
- `#spoof-panel` — enable/disable DNS spoof, add/remove domain→IP rules

**Dossier panel** fields: IP, MAC, vendor, hostname, OS (active + passive), TTL, country+flag, bandwidth, status, first/last seen, latency sparkline, open ports, CVE badges, device type, timeline.

### Event types (`internal/api/types.go`)

| Constant | Wire value | Key payload |
|---|---|---|
| `EventDeviceFound/Updated/Lost` | `device_found/updated/lost` | `device` |
| `EventFullState` | `full_state` | `devices`, `traffics`, `mitm_on` |
| `EventTraffic` | `traffic` | `traffic` |
| `EventBandwidth` | `bandwidth` | `bandwidth []BandwidthStat` |
| `EventPeerLink` | `peer_link` | `peer_links []PeerLinkPair` |
| `EventAlert` | `alert` | `alert` |
| `EventSSLStrip` | `ssl_strip` | `alert` |
| `EventMITMStatus` | `mitm_status` | `mitm_on` |
| `EventPassiveOS` | `passive_os` | `os_hints []OSHint` |
| `EventProbeDevice` | `probe_device` | `alert` |
| `EventScanStart/End` | `scan_start/end` | — |

### Device struct fields of note

`DeviceType string` — from mDNS (e.g. "Apple TV", "Chromecast", "Printer").
`TopoLayer int` — 0=gateway, 1=network device (SNMP/BGP ports or OS="Network Device"), 2=end device.
`CVEs []CVEEntry` — populated by `internal/cve.Match()` after port scan.
`PeerLinks []string` — IPs this device was seen communicating with directly.
`PingHistory []int` — last 20 RTTs in ms, -1=timeout.

### Scan cycle

Every 15s: ARP scan (3s) + mDNS (2s) in parallel. New devices: async `enrich()` — ping + port scan (50 goroutines) + CVE match + TopoLayer. Every 10s: `pingLoop()` re-pings all active devices.

### Data persistence

```
data/
  store.json                 # device geo, timelines — auto-saved every 30s
  sessions/YYYY-MM-DD.jsonl  # daily log: device_found/lost, alerts, MITM status
```
