// Package probe implements passive WiFi probe request scanning.
// It creates a temporary monitor interface to detect nearby devices
// (even those not connected to our network) via 802.11 probe requests.
package probe

import (
	"encoding/binary"
	"log"
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
)

const monIface = "mon0"

type ProbeScanner struct {
	srcIface string
	events   chan<- api.Event
	seen     map[string]time.Time
}

func New(iface string, events chan<- api.Event) *ProbeScanner {
	return &ProbeScanner{
		srcIface: iface,
		events:   events,
		seen:     make(map[string]time.Time),
	}
}

// Run creates a monitor interface and captures probe requests.
// Gracefully returns if the WiFi adapter doesn't support monitor mode.
func (p *ProbeScanner) Run() {
	if err := p.setup(); err != nil {
		log.Printf("ProbeScanner: monitor mode not available on %s (%v) — skipping", p.srcIface, err)
		return
	}
	defer p.teardown()

	iface, err := net.InterfaceByName(monIface)
	if err != nil {
		return
	}

	// ETH_P_ALL on monitor interface gives raw 802.11 frames with Radiotap header
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  iface.Index,
	})

	log.Printf("ProbeScanner: monitoring on %s", monIface)
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			break
		}
		p.processFrame(buf[:n])
	}
}

func (p *ProbeScanner) processFrame(frame []byte) {
	// Radiotap header: first 4 bytes, length in bytes 2-3
	if len(frame) < 4 {
		return
	}
	rtLen := int(binary.LittleEndian.Uint16(frame[2:4]))
	if len(frame) < rtLen+24 {
		return
	}
	dot11 := frame[rtLen:]

	// 802.11 Frame Control: byte 0
	// type = bits 2-3, subtype = bits 4-7
	fc := dot11[0]
	frameType    := (fc >> 2) & 0x03
	frameSubtype := (fc >> 4) & 0x0F

	// Probe Request: type=0 (Management), subtype=4
	if frameType != 0 || frameSubtype != 4 {
		return
	}
	if len(dot11) < 24 {
		return
	}

	// Address 2 = source MAC (bytes 10-15)
	srcMAC := net.HardwareAddr(dot11[10:16])
	macStr := srcMAC.String()

	// Deduplicate by MAC: show each device once per minute
	if t, ok := p.seen[macStr]; ok && time.Since(t) < 60*time.Second {
		return
	}
	p.seen[macStr] = time.Now()

	// Parse Information Elements for SSID (type 0)
	ssid := ""
	body := dot11[24:] // fixed params start at 24 for probe req
	// Skip 2-byte Listen Interval field
	if len(body) >= 2 {
		body = body[2:]
	}
	for len(body) >= 2 {
		ieType := body[0]
		ieLen := int(body[1])
		if len(body) < 2+ieLen {
			break
		}
		if ieType == 0 && ieLen > 0 {
			ssid = string(body[2 : 2+ieLen])
		}
		body = body[2+ieLen:]
	}

	msg := "Probe from " + macStr
	if ssid != "" {
		msg += " seeking '" + ssid + "'"
	}

	log.Printf("ProbeScanner: %s", msg)
	ev := api.AlertEvent{
		Level:   "info",
		Message: msg,
		IP:      macStr,
	}
	select {
	case p.events <- api.Event{Type: api.EventProbeDevice, Alert: &ev}:
	default:
	}
}

func (p *ProbeScanner) setup() error {
	// Add monitor interface
	if err := run("iw", "dev", p.srcIface, "interface", "add", monIface, "type", "monitor"); err != nil {
		return err
	}
	if err := run("ip", "link", "set", monIface, "up"); err != nil {
		run("iw", "dev", monIface, "del")
		return err
	}
	return nil
}

func (p *ProbeScanner) teardown() {
	run("ip", "link", "set", monIface, "down")
	run("iw", "dev", monIface, "del")
	log.Printf("ProbeScanner: removed %s", monIface)
}

func run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }
