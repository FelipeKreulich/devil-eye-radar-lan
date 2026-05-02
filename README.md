# LAN RADAR — devil eye

> Real-time LAN scanner with animated radar UI. Discovers devices via ARP, fingerprints OS/ports, captures DNS/HTTPS/HTTP traffic, performs ARP MITM, tracks bandwidth per host, and displays it all in a hacker-aesthetic Canvas dashboard. No libpcap required.

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

- **Animated radar** — Force-directed graph with sonar sweep, neon glow nodes, animated packet dots on edges
- **ARP scanner** — Discovers every IPv4 host on your LAN without libpcap (raw AF_PACKET sockets)
- **OS fingerprinting** — Active (ICMP TTL) + passive (TCP window/TTL from raw packets)
- **Port scanner** — Concurrent TCP connect scan of ~30 common ports with service banner grabbing
- **Traffic capture** — DNS queries, HTTPS SNI hostnames, HTTP Host headers in real time
- **ARP MITM** — Poison entire LAN via ARP spoofing + IP forwarding, intercept all traffic
- **Bandwidth monitor** — Per-host in/out rates with live heatmap on graph edges + 60-second history chart
- **Latency sparklines** — Ping history per device displayed in the node dossier
- **Threat detection** — ~40 known-bad domains/IPs (botnets, miners, RATs, phishing) flagged in red
- **ARP spoof detection** — Alerts when any IP changes MAC address
- **Port scan detection** — Alerts when >10 unique ports probed on your machine within 5s
- **Geo / flags** — Country + emoji flag for external IPs via ip-api.com (cached 24h)
- **mDNS / reverse DNS** — Hostname resolution without any external tools
- **WiFi probe monitor** — Captures 802.11 probe requests (nearby devices searching for networks)
- **Node pinning** — Right-click any node to lock its position on the canvas
- **Vendor clustering** — Nodes from the same manufacturer automatically drift together
- **Filter bar** — Filter visible nodes by status (active/ports/threat) or vendor name
- **Device timeline** — Online/offline history per device across sessions
- **Export** — Download all device data as JSON
- **Session log** — JSONL daily log in `data/sessions/` for post-analysis
- **CRT aesthetic** — Scanlines, neon green on black, monospace, Mr. Robot inspired

## Requirements

- Linux (uses `/proc/sys/net/ipv4/ip_forward`, AF_PACKET sockets, `iw`)
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

| Layer | Description |
|---|---|
| `internal/scanner` | ARP scan, mDNS, reverse DNS, ping, port scan, ARP spoof detection, latency history |
| `internal/sniffer` | Raw packet capture, DNS/TLS/HTTP parsing, bandwidth tracking, passive OS fingerprinting, port scan detection |
| `internal/mitm` | ARP poisoning, IP forwarding, graceful restore |
| `internal/probe` | 802.11 monitor mode, probe request capture |
| `internal/geo` | ip-api.com lookup with 24h cache |
| `internal/threat` | Static bad-domain/IP list |
| `internal/oui` | Static MAC vendor database (~600 prefixes) |
| `internal/store` | JSON persistence for device metadata across sessions |
| `internal/logger` | JSONL daily session log |
| `internal/api` | HTTP server, WebSocket hub, REST endpoints |
| `frontend/` | Single-file Canvas app (no build step, no dependencies) |

## REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/devices` | All known devices as JSON |
| `POST` | `/api/mitm/on` | Enable ARP MITM on all LAN targets |
| `POST` | `/api/mitm/off` | Disable MITM and restore ARP tables |
| `GET` | `/api/export` | Download device list as `lan-radar-export.json` |
| `GET` | `/ws` | WebSocket stream of all events |

## WebSocket events

| Event | Payload |
|---|---|
| `full_state` | All devices + recent traffic + MITM state |
| `device_found` | New IP discovered |
| `device_updated` | OS/ports/hostname/bandwidth updated |
| `device_lost` | Not seen for >10s |
| `traffic` | DNS/HTTPS/HTTP capture event |
| `bandwidth` | Per-IP in/out rates (every 1s) |
| `alert` | Toast notification (info/warning/danger) |
| `mitm_status` | MITM on/off state change |
| `passive_os` | OS guess from passive TCP fingerprinting |
| `probe_device` | 802.11 probe request from nearby device |
| `scan_start` / `scan_end` | Scan cycle indicator |

## Data persistence

```
data/
  store.json            # device labels, geo, timeline (saved every 30s)
  sessions/
    2025-01-15.jsonl    # daily event log (device_found, alerts, MITM events)
```

## Keyboard / mouse

| Action | Result |
|---|---|
| Click node | Open dossier panel |
| Drag node | Move it around |
| Right-click node | Pin / unpin position |
| Click empty space | Close dossier |
| SHOW filter buttons | Filter visible nodes |
| VENDOR input | Filter by manufacturer |

## License

MIT — see [LICENSE](LICENSE)
