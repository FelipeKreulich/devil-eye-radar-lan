package scanner

import (
	"math"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// PingResult holds ping outcome and TTL for OS fingerprinting.
type PingResult struct {
	Alive bool
	TTL   int
	OS    string
	RTT   int // round-trip time in ms; -1 if host is unreachable
}

// Ping uses the system `ping` command (works without root after ARP confirms host is up).
func Ping(ip string, timeout time.Duration) PingResult {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	out, err := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(secs), "-n", ip).Output()
	if err != nil {
		return PingResult{RTT: -1}
	}
	res := PingResult{Alive: true}
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "ttl=") {
			res.TTL = parseTTL(line)
			res.OS = guessOS(res.TTL)
		}
		if strings.Contains(lower, "time=") {
			res.RTT = parseRTT(line)
		}
		if res.TTL != 0 && res.RTT != 0 {
			break
		}
	}
	return res
}

func parseTTL(line string) int {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "ttl=")
	if idx < 0 {
		return 0
	}
	rest := lower[idx+4:]
	end := strings.IndexAny(rest, " \t\n")
	if end > 0 {
		rest = rest[:end]
	}
	v, _ := strconv.Atoi(strings.TrimSpace(rest))
	return v
}

func parseRTT(line string) int {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "time=")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimSpace(lower[idx+5:])
	// strip trailing unit (e.g. "ms", " ms")
	end := strings.IndexAny(rest, " \t\n")
	if end > 0 {
		rest = rest[:end]
	}
	rest = strings.TrimSuffix(rest, "ms")
	rest = strings.TrimSpace(rest)
	f, err := strconv.ParseFloat(rest, 64)
	if err != nil {
		return 0
	}
	return int(math.Round(f))
}

func guessOS(ttl int) string {
	switch {
	case ttl >= 250:
		return "Network Device (Cisco/Juniper)"
	case ttl >= 120:
		return "Windows"
	case ttl >= 60:
		return "Linux / macOS"
	case ttl > 0:
		return "Unknown"
	default:
		return ""
	}
}

// LocalGateway returns the default gateway IP.
func LocalGateway() net.IP {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil
	}
	// "default via X.X.X.X dev ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1])
		}
	}
	return nil
}
