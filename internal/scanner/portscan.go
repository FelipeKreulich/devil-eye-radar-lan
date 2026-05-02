package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
)

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000,
	27017, 6379, 5432, 1883, 5000, 4443, 8181,
}

var portNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
	1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
	9000: "HTTP-Alt", 27017: "MongoDB", 6379: "Redis",
	5432: "PostgreSQL", 1883: "MQTT", 5000: "UPnP",
	4443: "HTTPS-Alt", 8181: "HTTP-Alt",
}

// ScanPorts performs a concurrent TCP connect scan on commonPorts for a given IP.
func ScanPorts(ip string, timeout time.Duration) []api.Service {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var services []api.Service

	sem := make(chan struct{}, 50)

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			svc := api.Service{
				Port: p,
				Name: portNames[p],
			}
			svc.Banner = grabBanner(conn, p, timeout)

			mu.Lock()
			services = append(services, svc)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return services
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout / 2))
	switch port {
	case 80, 8080, 8888, 8181:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	case 443, 8443, 4443:
		return "TLS"
	case 22:
		// SSH sends banner first
	case 21, 25, 110, 143, 993, 995:
		// Protocol sends banner first
	default:
		return ""
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := scanner.Text()
		if len(line) > 80 {
			line = line[:80]
		}
		return strings.TrimSpace(line)
	}
	return ""
}
