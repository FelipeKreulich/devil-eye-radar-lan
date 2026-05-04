package scanner

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
	"github.com/antraz/devil-eye-lan-radar/internal/cve"
	"github.com/antraz/devil-eye-lan-radar/internal/geo"
	"github.com/antraz/devil-eye-lan-radar/internal/oui"
	"github.com/antraz/devil-eye-lan-radar/internal/store"
)

type Scanner struct {
	events  chan<- api.Event
	iface   *net.Interface
	gateway net.IP
	store   *store.Store

	mu      sync.Mutex
	devices map[string]*api.Device
}

func New(events chan<- api.Event, st *store.Store) (*Scanner, error) {
	iface, err := pickInterface()
	if err != nil {
		return nil, err
	}
	gw := LocalGateway()
	log.Printf("Scanner: interface=%s gateway=%s", iface.Name, gw)
	return &Scanner{
		events:  events,
		iface:   iface,
		gateway: gw,
		store:   st,
		devices: make(map[string]*api.Device),
	}, nil
}

func (s *Scanner) Iface() *net.Interface   { return s.iface }
func (s *Scanner) Gateway() net.IP         { return s.gateway }

// Devices returns a snapshot of all known devices for MITM registration.
func (s *Scanner) Devices() map[string]net.HardwareAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]net.HardwareAddr, len(s.devices))
	for ip, dev := range s.devices {
		mac, err := net.ParseMAC(dev.MAC)
		if err == nil {
			out[ip] = mac
		}
	}
	return out
}

func (s *Scanner) Run(interval time.Duration) {
	go s.pingLoop()
	for {
		s.scan()
		time.Sleep(interval)
	}
}

// pingLoop periodically pings all active devices and updates PingHistory.
func (s *Scanner) pingLoop() {
	for {
		time.Sleep(10 * time.Second)

		s.mu.Lock()
		ips := make([]string, 0, len(s.devices))
		for ip, dev := range s.devices {
			if dev.Active {
				ips = append(ips, ip)
			}
		}
		s.mu.Unlock()

		var wg sync.WaitGroup
		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				res := Ping(ip, 2*time.Second)
				rtt := res.RTT
				if !res.Alive {
					rtt = -1
				}

				s.mu.Lock()
				dev, ok := s.devices[ip]
				if ok {
					dev.PingHistory = append(dev.PingHistory, rtt)
					if len(dev.PingHistory) > 20 {
						dev.PingHistory = dev.PingHistory[len(dev.PingHistory)-20:]
					}
				}
				s.mu.Unlock()

				if ok {
					devCopy := *dev
					s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &devCopy}
				}
			}(ip)
		}
		wg.Wait()
	}
}

func (s *Scanner) scan() {
	s.events <- api.Event{Type: api.EventScanStart}

	macs, err := ARPScan(s.iface, 3*time.Second)
	if err != nil {
		log.Printf("ARP scan error: %v", err)
	}

	mdnsCh := make(chan struct{ h map[string]string; t map[string]string }, 1)
	go func() {
		h, t := MDNSQuery(2 * time.Second)
		mdnsCh <- struct{ h map[string]string; t map[string]string }{h, t}
	}()
	res := <-mdnsCh
	mdns := res.h
	mdnsTypes := res.t

	now := time.Now()
	seen := make(map[string]bool)

	for ip, mac := range macs {
		seen[ip] = true
		macStr := mac.String()
		vendor := oui.Lookup(macStr)

		hostname := mdns[ip]
		if hostname == "" {
			hostname = ReverseDNS(ip)
		}
		isGW := s.gateway != nil && s.gateway.String() == ip

		// Load persisted metadata
		meta := s.store.GetMeta(ip)

		s.mu.Lock()
		existing, ok := s.devices[ip]
		s.mu.Unlock()

		if !ok {
			dev := &api.Device{
				IP:          ip,
				MAC:         macStr,
				Hostname:    hostname,
				Vendor:      vendor,
				IsGateway:   isGW,
				Active:      true,
				FirstSeen:   now,
				LastSeen:    now,
				Label:       meta.Label,
				Country:     meta.Country,
				CountryCode: meta.Code,
				Timeline:    meta.Timeline,
				DeviceType:  mdnsTypes[ip],
			}
			go s.enrich(dev)

			s.mu.Lock()
			s.devices[ip] = dev
			s.mu.Unlock()

			s.store.RecordTimeline(ip, "online")

			devCopy := *dev
			s.events <- api.Event{Type: api.EventDeviceFound, Device: &devCopy}
			// Alert for new device
			s.events <- api.Event{Type: api.EventAlert, Alert: &api.AlertEvent{
				Level:   "warning",
				Message: "New device: " + ip + " (" + vendor + ")",
				IP:      ip,
			}}
			// Async geo lookup for device IP
			go func(d *api.Device) {
				info := geo.Lookup(d.IP)
				if info.Country == "" {
					return
				}
				s.mu.Lock()
				d.Country = info.Country
				d.CountryCode = info.CountryCode
				s.mu.Unlock()
				s.store.SetGeo(d.IP, info.Country, info.CountryCode)
				devCopy := *d
				s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &devCopy}
			}(dev)
		} else {
			changed := false
			s.mu.Lock()
			oldMAC := existing.MAC
			if macStr != oldMAC {
				existing.MAC = macStr
				changed = true
			}
			existing.LastSeen = now
			if !existing.Active {
				existing.Active = true
				changed = true
				go func(ip string) { s.store.RecordTimeline(ip, "online") }(ip)
			}
			if hostname != "" && existing.Hostname == "" {
				existing.Hostname = hostname
				changed = true
			}
			if !existing.IsGateway && isGW {
				existing.IsGateway = true
				changed = true
			}
			if meta.Label != "" && existing.Label == "" {
				existing.Label = meta.Label
				changed = true
			}
			if mdnsTypes[ip] != "" && existing.DeviceType == "" {
				existing.DeviceType = mdnsTypes[ip]
				changed = true
			}
			s.mu.Unlock()

			if macStr != oldMAC {
				s.events <- api.Event{Type: api.EventAlert, Alert: &api.AlertEvent{
					Level:   "danger",
					Message: "⚠ ARP SPOOFING: " + ip + " trocou MAC " + oldMAC + " → " + macStr,
					IP:      ip,
				}}
			}

			if changed {
				devCopy := *existing
				s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &devCopy}
			}
		}
	}

	s.mu.Lock()
	for ip, dev := range s.devices {
		if !seen[ip] && dev.Active && time.Since(dev.LastSeen) > 10*time.Second {
			dev.Active = false
			devCopy := *dev
			s.events <- api.Event{Type: api.EventDeviceLost, Device: &devCopy}
			go func(ip string) { s.store.RecordTimeline(ip, "offline") }(ip)
		}
	}
	s.mu.Unlock()

	s.events <- api.Event{Type: api.EventScanEnd}
}

func (s *Scanner) enrich(dev *api.Device) {
	pingRes := Ping(dev.IP, 2*time.Second)
	services := ScanPorts(dev.IP, 1*time.Second)

	// Assign topology layer
	topoLayer := 2
	if dev.IsGateway {
		topoLayer = 0
	} else {
		for _, svc := range services {
			if svc.Port == 161 || svc.Port == 179 || svc.Port == 520 {
				topoLayer = 1
				break
			}
		}
		if pingRes.OS == "Network Device (Cisco/Juniper)" {
			topoLayer = 1
		}
	}

	// CVE matching
	var cves []api.CVEEntry
	for _, svc := range services {
		for _, e := range cve.Match(svc.Port, svc.Banner) {
			cves = append(cves, api.CVEEntry{ID: e.ID, Severity: e.Severity, Desc: e.Desc})
		}
	}

	// SSL certificate inspection
	sslCerts := CheckSSL(dev.IP, services)

	s.mu.Lock()
	d, ok := s.devices[dev.IP]
	if ok {
		if pingRes.TTL > 0 {
			d.TTL = pingRes.TTL
			d.OS = pingRes.OS
		}
		d.OpenPorts = services
		d.TopoLayer = topoLayer
		d.CVEs = cves
		d.SSLCerts = sslCerts
		if d.DeviceType == "" {
			d.DeviceType = inferDeviceType(services, d.Vendor, d.IsGateway)
		}
	}
	s.mu.Unlock()

	if ok {
		devCopy := *d
		s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &devCopy}
	}
}

// ApplyBandwidth merges bandwidth stats into device objects and emits updates.
func (s *Scanner) ApplyBandwidth(stats []api.BandwidthStat) {
	s.mu.Lock()
	var updated []api.Device
	for _, stat := range stats {
		if d, ok := s.devices[stat.IP]; ok {
			d.RateIn = stat.RateIn
			d.RateOut = stat.RateOut
			d.BytesIn += int64(stat.RateIn)
			d.BytesOut += int64(stat.RateOut)
			updated = append(updated, *d)
		}
	}
	s.mu.Unlock()
	for i := range updated {
		d := updated[i]
		s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &d}
	}
}

// SetLabel persists a custom label for a device and emits an update.
func (s *Scanner) SetLabel(ip, label string) {
	s.store.SetLabel(ip, label)
	s.mu.Lock()
	dev, ok := s.devices[ip]
	if ok {
		dev.Label = label
	}
	s.mu.Unlock()
	if ok {
		devCopy := *dev
		s.events <- api.Event{Type: api.EventDeviceUpdated, Device: &devCopy}
	}
}

func inferDeviceType(services []api.Service, vendor string, isGateway bool) string {
	if isGateway {
		return "Gateway / Router"
	}
	ports := make(map[int]bool, len(services))
	for _, s := range services {
		ports[s.Port] = true
	}
	switch {
	case ports[3389]:
		return "Windows PC"
	case ports[62078]:
		return "iPhone / iPad"
	case ports[7000]:
		return "Apple TV / AirPlay"
	case ports[554]:
		return "IP Camera"
	case ports[9100]:
		return "Printer"
	case ports[1883] || ports[8883]:
		return "IoT Device (MQTT)"
	case ports[161]:
		return "Network Device"
	case ports[445] && ports[139]:
		return "Windows / NAS"
	case ports[22] && (ports[80] || ports[443] || ports[8080] || ports[8443]):
		return "Linux / Server"
	case ports[22]:
		return "Linux / Server"
	case ports[80] || ports[443] || ports[8080] || ports[8443]:
		return "Web Server"
	case ports[445]:
		return "Windows / NAS"
	case ports[23]:
		return "Network Device"
	}
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"):
		return "Apple Device"
	case strings.Contains(v, "samsung"):
		return "Samsung Device"
	case strings.Contains(v, "raspberry pi"):
		return "Linux / Server"
	case strings.Contains(v, "cisco") || strings.Contains(v, "juniper") ||
		strings.Contains(v, "mikrotik") || strings.Contains(v, "ubiquiti"):
		return "Network Device"
	case strings.Contains(v, "google"):
		return "Google Device"
	case strings.Contains(v, "amazon"):
		return "Amazon Device"
	case strings.Contains(v, "sony"):
		return "Sony Device"
	case strings.Contains(v, "lg ") || strings.Contains(v, "lg,"):
		return "LG Device"
	}
	return ""
}

func pickInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
				name := strings.ToLower(iface.Name)
				if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") {
					continue
				}
				return &iface, nil
			}
		}
	}
	return nil, nil
}
