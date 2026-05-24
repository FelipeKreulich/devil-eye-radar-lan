package scanner

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
	"time"
)

type NDPEntry struct {
	IP net.IP
	MAC net.HardwareAddr
}

// NDPScan pings the all-nodes multicast to stimulate NDP responses,
// then reads the kernel neighbor cache for the given interface.
func NDPScan(iface *net.Interface, timeout time.Duration) ([]NDPEntry, error) {
	// Trigger Neighbor Advertisements from all IPv6 hosts
	cmd := exec.Command("ping6", "-c", "2", "-W", "1", "-I", iface.Name, "ff02::1")
	cmd.Run() // Erro ignorado - So quero popular o cache

	time.Sleep(timeout / 2)

	out, err := exec.Command("ip", "-6", "neigh", "show", "dev", iface.Name).Output()
	if err != nil {
		return nil, err
	}

	return parseNeighCache(string(out)), nil
}

// MACToIPv6 builds a MAC -> []IPv6 lookup map from NDPScan results.
func MACToIPv6(entries []NDPEntry) map[string][]string {
	m := make(map[string][]string)
	for _, e := range entries {
		key := e.MAC.String()
		m[key] = append(m[key], e.IP.String())
	}
	return m
}

// parseNeighCache parses ip -6 neigh show output.
// Format: "2001:db8::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
func parseNeighCache(output string) []NDPEntry {
	var entries []NDPEntry
	seen := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		var mac net.HardwareAddr
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				m, err := net.ParseMAC(fields[i+1])
				if err == nil {
					mac = m
				}
			}
		}
		if mac == nil {
			continue
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, NDPEntry{IP: ip, MAC: mac})
	}
	return entries
}
