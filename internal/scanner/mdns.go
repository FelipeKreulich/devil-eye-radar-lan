package scanner

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// serviceTypes maps mDNS service labels to human-readable device type strings.
var serviceTypes = map[string]string{
	"_airplay._tcp":         "Apple TV / AirPlay",
	"_googlecast._tcp":      "Chromecast / Google TV",
	"_ipp._tcp":             "Printer (IPP)",
	"_pdl-datastream._tcp":  "Printer (PDL)",
	"_printer._tcp":         "Printer",
	"_ssh._tcp":             "Linux / Server",
	"_sftp-ssh._tcp":        "Linux / Server",
	"_smb._tcp":             "Windows / NAS",
	"_companion-link._tcp":  "Apple Device",
	"_apple-mobdev2._tcp":   "iPhone / iPad",
	"_daap._tcp":            "iTunes Server",
	"_raop._tcp":            "AirPlay Audio",
	"_homekit._tcp":         "HomeKit Device",
	"_hap._tcp":             "HomeKit Accessory",
	"_workstation._tcp":     "Workstation",
	"_spotify-connect._tcp": "Spotify Device",
	"_sonos._tcp":           "Sonos Speaker",
	"_axis-video._tcp":      "IP Camera",
	"_rtsp._tcp":            "IP Camera / Media",
	"_xbox._tcp":            "Xbox",
	"_nvstream_dbd._tcp":    "NVIDIA Shield",
	"_philips-hue._tcp":     "Philips Hue",
}

// MDNSQuery sends a multicast DNS query for PTR records and returns:
//   - hostnames: IP → hostname
//   - deviceTypes: IP → DeviceType string (inferred from mDNS service advertisements)
func MDNSQuery(timeout time.Duration) (hostnames map[string]string, deviceTypes map[string]string) {
	hostnames = make(map[string]string)
	deviceTypes = make(map[string]string)

	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	})
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send PTR query for _services._dns-sd._udp.local
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	msg.RecursionDesired = false

	buf, err := msg.Pack()
	if err != nil {
		return
	}
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	wconn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return
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
		remoteIP := addr.IP.String()

		// Collect A record mappings from this message: name → ip
		aRecords := make(map[string]string)
		for _, rr := range append(resp.Answer, resp.Extra...) {
			if a, ok := rr.(*dns.A); ok {
				aRecords[strings.ToLower(a.Hdr.Name)] = a.A.String()
			}
		}

		for _, rr := range append(resp.Answer, resp.Extra...) {
			switch v := rr.(type) {
			case *dns.A:
				name := strings.TrimSuffix(v.Hdr.Name, ".local.")
				name = strings.TrimSuffix(name, ".")
				hostnames[v.A.String()] = name

			case *dns.AAAA:
				name := strings.TrimSuffix(v.Hdr.Name, ".local.")
				name = strings.TrimSuffix(name, ".")
				if v.AAAA.To4() != nil {
					hostnames[v.AAAA.String()] = name
				}

			case *dns.PTR:
				// v.Hdr.Name is the service type (e.g. "_airplay._tcp.local.")
				// v.Ptr is the instance name (e.g. "MyDevice._airplay._tcp.local.")
				svcLabel := extractServiceLabel(v.Hdr.Name)
				devType, known := serviceTypes[svcLabel]
				if !known {
					// fallback: record hostname from PTR name
					name := strings.TrimSuffix(v.Ptr, ".local.")
					name = strings.TrimSuffix(name, ".")
					if _, exists := hostnames[remoteIP]; !exists && remoteIP != "" {
						hostnames[remoteIP] = name
					}
					continue
				}

				// Try to find the IP for this device via SRV → A record correlation.
				// Look for a matching A record by checking the instance host part.
				ipForService := ""

				// Check SRV records in the same message to find the target host
				for _, srr := range append(resp.Answer, resp.Extra...) {
					if srv, ok := srr.(*dns.SRV); ok {
						// SRV Hdr.Name is the instance (e.g. "MyDevice._airplay._tcp.local.")
						if strings.HasSuffix(strings.ToLower(srv.Hdr.Name), strings.ToLower(svcLabel+".local.")) {
							target := strings.ToLower(srv.Target)
							if ip, ok := aRecords[target]; ok {
								ipForService = ip
								break
							}
						}
					}
				}

				// If no SRV correlation, try direct A record lookup for the instance name
				if ipForService == "" {
					instanceName := strings.ToLower(v.Ptr)
					for aName, aIP := range aRecords {
						if strings.HasPrefix(instanceName, strings.TrimSuffix(aName, ".")) {
							ipForService = aIP
							break
						}
					}
				}

				// Fall back to the remote IP of the DNS packet
				if ipForService == "" {
					ipForService = remoteIP
				}

				if ipForService != "" {
					if _, already := deviceTypes[ipForService]; !already {
						deviceTypes[ipForService] = devType
					}
				}
			}
		}
	}
	return
}

// extractServiceLabel strips the trailing ".local." and returns the service label
// portion, e.g. "_airplay._tcp.local." → "_airplay._tcp".
func extractServiceLabel(name string) string {
	s := strings.ToLower(name)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".local")
	return s
}

// ReverseDNS attempts a reverse DNS lookup for an IP.
func ReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
