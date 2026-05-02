package scanner

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// MDNSQuery sends a multicast DNS query for PTR records and returns IP->hostname map.
func MDNSQuery(timeout time.Duration) map[string]string {
	results := make(map[string]string)

	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	})
	if err != nil {
		return results
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send PTR query for _services._dns-sd._udp.local
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	msg.RecursionDesired = false

	buf, err := msg.Pack()
	if err != nil {
		return results
	}
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	wconn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return results
	}
	wconn.Write(buf)
	wconn.Close()

	readBuf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFromUDP(readBuf)
		if err != nil {
			break
		}
		var resp dns.Msg
		if err := resp.Unpack(readBuf[:n]); err != nil {
			continue
		}
		ip := addr.IP.String()
		for _, rr := range append(resp.Answer, resp.Extra...) {
			switch v := rr.(type) {
			case *dns.A:
				name := strings.TrimSuffix(v.Hdr.Name, ".local.")
				name = strings.TrimSuffix(name, ".")
				results[v.A.String()] = name
			case *dns.AAAA:
				name := strings.TrimSuffix(v.Hdr.Name, ".local.")
				name = strings.TrimSuffix(name, ".")
				if v.AAAA.To4() != nil {
					results[v.AAAA.String()] = name
				}
			case *dns.PTR:
				if ip != "" {
					name := strings.TrimSuffix(v.Ptr, ".local.")
					name = strings.TrimSuffix(name, ".")
					if _, exists := results[ip]; !exists {
						results[ip] = name
					}
				}
			}
		}
	}
	return results
}

// ReverseDNS attempts a reverse DNS lookup for an IP.
func ReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
