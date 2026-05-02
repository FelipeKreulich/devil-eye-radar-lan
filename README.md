# LAN RADAR — devil eye

> Real-time LAN scanner with animated radar UI. Discovers devices via ARP, fingerprints OS/ports, captures DNS/HTTPS/HTTP traffic, performs ARP MITM, DNS spoofing, CVE detection, topology mapping and more — all in a hacker-aesthetic Canvas dashboard. No libpcap required.

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-black?style=flat-square)

```
╔══════════════════════════════════════════════════════╗
║  ▶ LAN RADAR // DEVIL EYE                            ║
║  Live animated network map for your local network    ║
╚══════════════════════════════════════════════════════╝
```

## Features

### Discovery & Fingerprinting
- **ARP scanner** — Discovers every IPv4 host without libpcap (raw AF_PACKET sockets)
- **OS fingerprinting** — Active (ICMP TTL) + passive (TCP window/TTL from raw packets)
- **mDNS device typing** — Identifies device types from Bonjour/mDNS service records (`_airplay._tcp` → Apple TV, `_googlecast._tcp` → Chromecast, etc.)
- **Port scanner** — Concurrent TCP connect scan of ~30 common ports with banner grabbing
- **CVE scanner** — Matches service banners against 21+ known CVEs (EternalBlue, Ghostcat, vsftpd backdoor, etc.)

### Traffic Analysis
- **Packet capture** — DNS queries, HTTPS SNI hostnames, HTTP Host headers in real time
- **Bandwidth monitor** — Per-host in/out rates with animated heatmap on graph edges
- **Traffic correlation** — Detects direct device-to-device LAN communication, visualized as dashed edges
- **Threat detection** — ~40 known-bad domains/IPs flagged in real time (botnets, miners, RATs)

### Security / Offensive
- **ARP MITM** — Poison entire LAN via ARP spoofing + IP forwarding; graceful ARP restore on stop
- **DNS spoofing** — Intercept and redirect DNS queries from any LAN device (via iptables redirect + custom resolver)
- **SSL stripping detection** — Alerts when a device accesses a domain via HTTP that it previously used HTTPS for
- **ARP spoof detection** — Alerts when any IP changes its MAC address
- **Port scan detection** — Alerts when >10 unique ports are probed from the same source within 5s
- **Rogue DHCP detection** — Alerts on unauthorized DHCP servers on the LAN
- **WiFi probe monitor** — Captures 802.11 probe requests from nearby devices

### Visualization
- **Animated radar** — Force-directed graph with sonar sweep, neon glow, animated packet dots
- **Topology mode** — Switch to concentric-ring layout: gateway → network devices → end devices
- **Heatmap overlay** — Additive glow per node based on real-time traffic volume
- **Vendor clustering** — Nodes from the same manufacturer drift together automatically
- **Bandwidth chart** — 60-second history bar chart (canvas, bottom-right)
- **Latency sparklines** — Ping RTT history per device in the dossier panel
- **Peer link edges** — Dashed lines between devices communicating directly

### Data & History
- **Statistics dashboard** — Total devices, top domains, busiest hosts, encryption ratio, total bytes
- **Session replay** — Load any past session from JSONL log and replay it as an animation
- **Persistent session log** — JSONL daily log in `data/sessions/` for post-analysis
- **Device timeline** — Online/offline history per device across sessions
- **Geo / flags** — Country + emoji flag for external IPs
- **Export** — Download all device data as JSON

### UI
- **Filter bar** — Filter nodes by status (ALL/ACTIVE/PORTS OPEN/THREAT) or vendor name
- **Node pinning** — Right-click any node to lock its position
- **Toast notifications** — Severity-colored alerts (info/warning/danger)
- **CRT aesthetic** — Scanlines, neon green on black, monospace, Mr. Robot inspired

## Requirements

- Linux (uses `/proc/sys/net/ipv4/ip_forward`, AF_PACKET sockets, `iptables`, `iw`)
- Go 1.22+
- Chromium browser
- Root or `cap_net_raw` capability

## Quick start

```bash
# Build
make build

# Run (requires root for raw sockets)
make run
# or: sudo -E ./lan-radar
```

Chromium opens automatically as a desktop app window on `http://127.0.0.1:7777`.

To avoid `sudo` every time:
```bash
make install-cap   # sets cap_net_raw on the binary (run once)
./lan-radar
```

## Build commands

```bash
make build        # go mod tidy + compile → ./lan-radar
make build-dev    # same with -race detector
make run          # build + sudo -E ./lan-radar
make install-cap  # build + setcap cap_net_raw+ep (avoids sudo)
make clean
```

## Architecture

```
Scanner ──┐
Sniffer ──┼──▶  hub.Events (chan)  ──▶  Hub.RunBroadcastLoop()  ──▶  WebSocket  ──▶  Browser
Probe   ──┘                                     │
                                          Hub.devices (map)
                                          Hub.logger → data/sessions/YYYY-MM-DD.jsonl
```

| Package | Description |
|---|---|
| `internal/scanner` | ARP scan, mDNS fingerprint, port scan, CVE matching, OS detection, ARP spoof detection, latency history |
| `internal/sniffer` | Raw packet capture, DNS/TLS/HTTP parsing, bandwidth, passive OS, port scan detection, DHCP rogue, traffic correlation, SSL strip detection |
| `internal/mitm` | ARP poisoning, IP forwarding, graceful restore |
| `internal/dnsspoof` | DNS interception via iptables + custom resolver with per-domain spoof rules |
| `internal/cve` | Static CVE database, banner-based matching |
| `internal/probe` | 802.11 monitor mode, probe request capture |
| `internal/geo` | ip-api.com lookup, 24h cache, emoji flags |
| `internal/threat` | Static bad-domain/IP list |
| `internal/oui` | MAC vendor database (~600 prefixes) |
| `internal/store` | JSON persistence for device metadata |
| `internal/logger` | JSONL daily session log |
| `internal/api` | HTTP server, WebSocket hub, REST endpoints |
| `frontend/` | Single-file Canvas app (no build step, no dependencies) |

## REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/devices` | All known devices |
| `POST` | `/api/mitm/on` | Enable ARP MITM |
| `POST` | `/api/mitm/off` | Disable MITM and restore ARP |
| `GET` | `/api/export` | Download device list as JSON |
| `GET` | `/api/sessions` | List available session dates |
| `GET` | `/api/sessions/{date}` | Download JSONL session log |
| `GET` | `/api/dnsspoof/status` | DNS spoof state + active rules |
| `POST` | `/api/dnsspoof/on` | Enable DNS spoofing |
| `POST` | `/api/dnsspoof/off` | Disable DNS spoofing |
| `POST` | `/api/dnsspoof/rules` | Add spoof rule `{domain, ip}` |
| `DELETE` | `/api/dnsspoof/rules` | Remove rule `{domain}` |
| `GET` | `/ws` | WebSocket event stream |

## WebSocket events

| Event | Payload |
|---|---|
| `full_state` | All devices + recent traffic + MITM state |
| `device_found/updated/lost` | Device object |
| `traffic` | DNS/HTTPS/HTTP capture |
| `bandwidth` | Per-IP rates (every 1s) |
| `peer_link` | Device-to-device pairs (every 10s) |
| `alert` | Toast notification (info/warning/danger) |
| `mitm_status` | MITM on/off |
| `ssl_strip` | SSL downgrade detected |
| `passive_os` | OS guess from TCP fingerprinting |
| `probe_device` | 802.11 probe request |
| `scan_start/end` | Scan cycle indicator |

## Keyboard / mouse

| Action | Result |
|---|---|
| Click node | Open dossier panel |
| Drag node | Move it around |
| Right-click node | Pin / unpin position |
| Click empty space | Close dossier |
| ⬡ TOPO button | Toggle topology layout mode |
| ◉ HEAT button | Toggle heatmap overlay |
| ≡ STATS button | Open statistics dashboard |
| ⏪ REPLAY button | Open session replay panel |
| ⚡ SPOOF button | Open DNS spoof rules panel |

## Data persistence

```
data/
  store.json                 # device geo, timelines — saved every 30s
  sessions/YYYY-MM-DD.jsonl  # daily event log (device events, alerts, MITM)
```

## License

MIT — see [LICENSE](LICENSE)
