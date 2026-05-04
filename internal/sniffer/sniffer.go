package sniffer

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
	"github.com/antraz/devil-eye-lan-radar/internal/geo"
	"github.com/antraz/devil-eye-lan-radar/internal/threat"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }

// ─── Bandwidth tracker ────────────────────────────────────────────────────────

type bwKey struct{ ip string; out bool }
type bwBucket struct {
	bytes int64
	ts    time.Time
}

type BandwidthTracker struct {
	mu      sync.Mutex
	samples map[bwKey][]bwBucket // sliding window: last 5s buckets
}

func newBandwidthTracker() *BandwidthTracker {
	return &BandwidthTracker{samples: make(map[bwKey][]bwBucket)}
}

func (b *BandwidthTracker) record(ip string, out bool, bytes int) {
	k := bwKey{ip, out}
	b.mu.Lock()
	b.samples[k] = append(b.samples[k], bwBucket{int64(bytes), time.Now()})
	b.mu.Unlock()
}

// flush returns per-IP rates (bytes/sec) and resets counts older than 1s.
func (b *BandwidthTracker) flush() []api.BandwidthStat {
	now := time.Now()
	cutoff := now.Add(-1 * time.Second)

	b.mu.Lock()
	byIP := make(map[string]*[2]int64) // ip → [in, out]
	for k, buckets := range b.samples {
		var sum int64
		var kept []bwBucket
		for _, bkt := range buckets {
			if bkt.ts.After(cutoff) {
				sum += bkt.bytes
				kept = append(kept, bkt)
			}
		}
		if len(kept) == 0 {
			delete(b.samples, k)
			continue
		}
		b.samples[k] = kept
		if byIP[k.ip] == nil {
			v := [2]int64{}
			byIP[k.ip] = &v
		}
		if k.out {
			byIP[k.ip][1] += sum
		} else {
			byIP[k.ip][0] += sum
		}
	}
	b.mu.Unlock()

	stats := make([]api.BandwidthStat, 0, len(byIP))
	for ip, v := range byIP {
		stats = append(stats, api.BandwidthStat{
			IP:      ip,
			RateIn:  float64(v[0]),
			RateOut: float64(v[1]),
		})
	}
	return stats
}

// ─── Sniffer ──────────────────────────────────────────────────────────────────

type Sniffer struct {
	events chan<- api.Event
	iface  *net.Interface
	bw     *BandwidthTracker

	dedupMu sync.Mutex
	seen    map[string]time.Time

	scanMu    sync.Mutex
	scanTrack map[string]map[uint16]time.Time // srcIP → dstPort → firstSeen
	ownIPs    map[string]bool

	osMu    sync.Mutex
	osCache map[string]string // ip → last emitted OS

	peerMu    sync.Mutex
	peerLinks map[string]map[string]int64 // srcIP → dstIP → bytes
	peerTick  time.Time

	sslMu    sync.RWMutex
	httpsSet map[string]map[string]bool // srcIP → set of HTTPS hosts seen
}

// buildOwnIPs returns a set of IPv4 addresses belonging to the given interface.
func buildOwnIPs(iface *net.Interface) map[string]bool {
	own := make(map[string]bool)
	addrs, err := iface.Addrs()
	if err != nil {
		return own
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			own[ip4.String()] = true
		}
	}
	return own
}

func New(iface *net.Interface, events chan<- api.Event) *Sniffer {
	s := &Sniffer{
		events:    events,
		iface:     iface,
		bw:        newBandwidthTracker(),
		seen:      make(map[string]time.Time),
		scanTrack: make(map[string]map[uint16]time.Time),
		ownIPs:    buildOwnIPs(iface),
		osCache:   make(map[string]string),
		peerLinks: make(map[string]map[string]int64),
		peerTick:  time.Now(),
		httpsSet:  make(map[string]map[string]bool),
	}
	go s.cleanupLoop()
	go s.bwLoop()
	return s
}

func (s *Sniffer) Run() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		log.Printf("sniffer: socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  s.iface.Index,
	}); err != nil {
		log.Printf("sniffer: bind: %v", err)
		return
	}

	// Enable promiscuous mode so we capture forwarded MITM traffic from other devices.
	mreq := unix.PacketMreq{
		Ifindex: int32(s.iface.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		log.Printf("sniffer: promisc: %v", err)
	}

	log.Printf("Sniffer: capturing on %s (promiscuous)", s.iface.Name)

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Printf("sniffer: recv: %v", err)
			break
		}
		s.processFrame(buf[:n])
	}
}

func (s *Sniffer) processFrame(frame []byte) {
	if len(frame) < 14 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return
	}
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+8 {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()

	// Bandwidth tracking
	s.bw.record(srcIP, true, totalLen)
	s.bw.record(dstIP, false, totalLen)

	// Track LAN-to-LAN communication
	if isPrivateIP(srcIP) && isPrivateIP(dstIP) && srcIP != dstIP {
		s.trackPeer(srcIP, dstIP, int64(totalLen))
	}

	s.inferOS(srcIP, ip)

	switch ip[9] {
	case 17:
		s.handleUDP(srcIP, dstIP, ip[ihl:])
	case 6:
		s.handleTCP(srcIP, dstIP, ip[ihl:])
	}
}

// ─── UDP / DNS ────────────────────────────────────────────────────────────────

func (s *Sniffer) handleUDP(srcIP, dstIP string, seg []byte) {
	if len(seg) < 8 {
		return
	}
	sp := binary.BigEndian.Uint16(seg[0:2])
	dp := binary.BigEndian.Uint16(seg[2:4])
	if sp == 53 || dp == 53 {
		s.parseDNS(srcIP, dstIP, seg[8:])
	}
	if (sp == 67 || sp == 68) && (dp == 67 || dp == 68) {
		s.checkRogueDHCP(srcIP, seg[8:])
	}
}

func (s *Sniffer) parseDNS(srcIP, dstIP string, data []byte) {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return
	}
	for _, q := range msg.Question {
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}
		domain := strings.TrimSuffix(q.Name, ".")
		if !s.dedup("dns:"+domain, 8*time.Second) {
			continue
		}
		ev := s.buildTraffic(srcIP, dstIP, "DNS", domain, "")
		s.emit(api.Event{Type: api.EventTraffic, Traffic: &ev})
	}
	if msg.Response {
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				domain := strings.TrimSuffix(rr.Header().Name, ".")
				key := "dns-ans:" + domain + ":" + a.A.String()
				if !s.dedup(key, 60*time.Second) {
					continue
				}
				ev := s.buildTraffic(srcIP, dstIP, "DNS", domain, "→ "+a.A.String())
				s.emit(api.Event{Type: api.EventTraffic, Traffic: &ev})
			}
		}
	}
}

// ─── TCP / TLS / HTTP ─────────────────────────────────────────────────────────

func (s *Sniffer) handleTCP(srcIP, dstIP string, seg []byte) {
	if len(seg) < 20 {
		return
	}
	sp := binary.BigEndian.Uint16(seg[0:2])
	dp := binary.BigEndian.Uint16(seg[2:4])

	// Port scan detection: SYN-only (SYN set, ACK not set)
	flags := seg[13]
	isSYN := (flags&0x02 != 0) && (flags&0x10 == 0)
	if isSYN && s.ownIPs[dstIP] {
		s.trackPortScan(srcIP, dp)
	}

	off := int(seg[12]>>4) * 4
	if off < 20 || len(seg) < off {
		return
	}
	payload := seg[off:]
	if len(payload) == 0 {
		return
	}
	switch {
	case dp == 443 || sp == 443 || dp == 8443 || sp == 8443:
		if sni := parseTLSSNI(payload); sni != "" {
			s.sslMu.Lock()
			if s.httpsSet[srcIP] == nil {
				s.httpsSet[srcIP] = make(map[string]bool)
			}
			s.httpsSet[srcIP][sni] = true
			s.sslMu.Unlock()
			key := "tls:" + dstIP + ":" + sni
			if s.dedup(key, 30*time.Second) {
				ev := s.buildTraffic(srcIP, dstIP, "HTTPS", sni, "")
				s.emit(api.Event{Type: api.EventTraffic, Traffic: &ev})
			}
		}
	case dp == 80 || sp == 80 || dp == 8080 || sp == 8080:
		if host := parseHTTPHost(payload); host != "" {
			s.sslMu.RLock()
			_, wasHTTPS := s.httpsSet[srcIP][host]
			s.sslMu.RUnlock()
			if wasHTTPS {
				if s.dedup("sslstrip:"+srcIP+":"+host, 60*time.Second) {
					s.emit(api.Event{Type: api.EventSSLStrip, Alert: &api.AlertEvent{
						Level:   "danger",
						Message: "⚠ SSL STRIP: " + srcIP + " acessando " + host + " via HTTP (antes era HTTPS)",
						IP:      srcIP,
					}})
				}
			}
			key := "http:" + dstIP + ":" + host
			if s.dedup(key, 30*time.Second) {
				ev := s.buildTraffic(srcIP, dstIP, "HTTP", host, "")
				s.emit(api.Event{Type: api.EventTraffic, Traffic: &ev})
			}
		}
	}
}

// ─── Enrichment ───────────────────────────────────────────────────────────────

func (s *Sniffer) buildTraffic(srcIP, dstIP, proto, domain, details string) api.TrafficEvent {
	ev := api.TrafficEvent{
		Time:    time.Now(),
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Proto:   proto,
		Domain:  domain,
		Details: details,
	}
	// Geo lookup for external destination
	if domain != "" {
		if ok, hit := threat.Check(domain); ok {
			ev.Threat = true
			ev.ThreatMsg = "[" + hit.Category + "] " + hit.Message
		}
	}
	// Geo: use cached result synchronously; warm cache async on miss
	if info := geo.LookupCached(dstIP); info.Country != "" {
		ev.Country = info.Country
		ev.CountryCode = info.CountryCode
		ev.Flag = info.Flag
	} else if !isPrivateIP(dstIP) {
		go geo.Lookup(dstIP)
	}
	return ev
}

// ─── Bandwidth loop ───────────────────────────────────────────────────────────

func (s *Sniffer) bwLoop() {
	for range time.Tick(1 * time.Second) {
		stats := s.bw.flush()
		if len(stats) > 0 {
			s.emit(api.Event{Type: api.EventBandwidth, Bandwidth: stats})
		}
	}
}

// ─── TLS SNI parser ───────────────────────────────────────────────────────────

func parseTLSSNI(b []byte) string {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return ""
	}
	hs := b[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4:]
	if len(body) < 35 {
		return ""
	}
	p := 34
	p += 1 + int(body[34])
	if len(body) < p+2 {
		return ""
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:]))
	if len(body) < p+1 {
		return ""
	}
	p += 1 + int(body[p])
	if len(body) < p+2 {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	end := p + extTotal
	for p+4 <= end && p+4 <= len(body) {
		extType := binary.BigEndian.Uint16(body[p:])
		extLen := int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+extLen > len(body) {
			break
		}
		if extType == 0x0000 && extLen >= 5 && body[p+2] == 0x00 {
			nameLen := int(binary.BigEndian.Uint16(body[p+3:]))
			if p+5+nameLen <= len(body) {
				return string(body[p+5 : p+5+nameLen])
			}
		}
		p += extLen
	}
	return ""
}

func parseHTTPHost(b []byte) string {
	s := string(b)
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "\nhost: ")
	if idx < 0 {
		return ""
	}
	start := idx + 7
	end := strings.IndexAny(s[start:], "\r\n")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(s[start : start+end])
}

// ─── Port scan detection ──────────────────────────────────────────────────────

func (s *Sniffer) trackPortScan(srcIP string, port uint16) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	if s.scanTrack[srcIP] == nil {
		s.scanTrack[srcIP] = make(map[uint16]time.Time)
	}
	s.scanTrack[srcIP][port] = time.Now()

	// Prune entries older than 5s
	cutoff := time.Now().Add(-5 * time.Second)
	for p, t := range s.scanTrack[srcIP] {
		if t.Before(cutoff) {
			delete(s.scanTrack[srcIP], p)
		}
	}

	count := len(s.scanTrack[srcIP])
	if count > 10 {
		msg := "🔍 PORT SCAN: " + srcIP + " sondando " + strconv.Itoa(count) + " portas"
		delete(s.scanTrack, srcIP) // clear to avoid repeated alerts
		s.emit(api.Event{Type: api.EventAlert, Alert: &api.AlertEvent{
			Level:   "danger",
			Message: msg,
			IP:      srcIP,
		}})
	}
}

// ─── Passive OS fingerprinting ────────────────────────────────────────────────

func (s *Sniffer) inferOS(srcIP string, ipHdr []byte) {
	if len(ipHdr) < 20 {
		return
	}
	ihl := int(ipHdr[0]&0x0f) * 4
	ttl := int(ipHdr[8])

	var guess string
	if ipHdr[9] == 6 && len(ipHdr) >= ihl+16 {
		window := binary.BigEndian.Uint16(ipHdr[ihl+14 : ihl+16])
		switch {
		case ttl >= 120 && window == 65535:
			guess = "Windows"
		case ttl >= 120 && window >= 8192:
			guess = "Windows"
		case ttl >= 60 && ttl < 70 && window >= 5000:
			guess = "Linux / macOS"
		case ttl >= 60 && ttl < 70:
			guess = "Linux / macOS"
		case ttl >= 250:
			guess = "Network Device"
		default:
			return
		}
	} else {
		switch {
		case ttl >= 120:
			guess = "Windows"
		case ttl >= 60 && ttl < 70:
			guess = "Linux / macOS"
		case ttl >= 250:
			guess = "Network Device"
		default:
			return
		}
	}

	s.osMu.Lock()
	prev := s.osCache[srcIP]
	if prev == guess {
		s.osMu.Unlock()
		return
	}
	s.osCache[srcIP] = guess
	s.osMu.Unlock()

	s.emit(api.Event{Type: api.EventPassiveOS, OSHints: []api.OSHint{{IP: srcIP, OS: guess}}})
}

// ─── Dedup & helpers ──────────────────────────────────────────────────────────

func (s *Sniffer) dedup(key string, ttl time.Duration) bool {
	s.dedupMu.Lock()
	defer s.dedupMu.Unlock()
	if t, ok := s.seen[key]; ok && time.Since(t) < ttl {
		return false
	}
	s.seen[key] = time.Now()
	return true
}

func (s *Sniffer) cleanupLoop() {
	for range time.Tick(60 * time.Second) {
		s.dedupMu.Lock()
		for k, t := range s.seen {
			if time.Since(t) > 120*time.Second {
				delete(s.seen, k)
			}
		}
		s.dedupMu.Unlock()
	}
}

func (s *Sniffer) emit(ev api.Event) {
	select {
	case s.events <- ev:
	default:
	}
}

// ─── Private IP helper ────────────────────────────────────────────────────────

var (
	privateRanges = []net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
	}
)

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, r := range privateRanges {
		if r.Contains(ip4) {
			return true
		}
	}
	return false
}

// ─── Peer link tracker ────────────────────────────────────────────────────────

func (s *Sniffer) trackPeer(srcIP, dstIP string, bytes int64) {
	s.peerMu.Lock()
	if s.peerLinks[srcIP] == nil {
		s.peerLinks[srcIP] = make(map[string]int64)
	}
	s.peerLinks[srcIP][dstIP] += bytes
	flush := time.Since(s.peerTick) > 10*time.Second
	if flush {
		var pairs []api.PeerLinkPair
		for src, dsts := range s.peerLinks {
			for dst, b := range dsts {
				pairs = append(pairs, api.PeerLinkPair{SrcIP: src, DstIP: dst, Bytes: b})
			}
		}
		s.peerLinks = make(map[string]map[string]int64)
		s.peerTick = time.Now()
		s.peerMu.Unlock()
		if len(pairs) > 0 {
			s.emit(api.Event{Type: api.EventPeerLink, PeerLinks: pairs})
		}
		return
	}
	s.peerMu.Unlock()
}

// ─── Rogue DHCP detection ─────────────────────────────────────────────────────

func (s *Sniffer) checkRogueDHCP(srcIP string, data []byte) {
	if len(data) < 240 {
		return
	}
	// Check DHCP magic cookie at offset 236
	if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
		return
	}
	// Parse options looking for option 53 (DHCP message type)
	i := 240
	for i < len(data)-1 {
		opt := data[i]
		if opt == 255 {
			break
		} // END
		if opt == 0 {
			i++
			continue
		} // PAD
		if i+1 >= len(data) {
			break
		}
		ln := int(data[i+1])
		if i+2+ln > len(data) {
			break
		}
		if opt == 53 && ln == 1 {
			msgType := data[i+2]
			if msgType == 2 || msgType == 5 { // OFFER or ACK
				if s.dedup("dhcp:"+srcIP, 60*time.Second) {
					s.emit(api.Event{Type: api.EventAlert, Alert: &api.AlertEvent{
						Level:   "danger",
						Message: "⚠ ROGUE DHCP: servidor DHCP não autorizado em " + srcIP,
						IP:      srcIP,
					}})
				}
			}
		}
		i += 2 + ln
	}
}
