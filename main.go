package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
	"github.com/antraz/devil-eye-lan-radar/internal/dnsspoof"
	"github.com/antraz/devil-eye-lan-radar/internal/logger"
	"github.com/antraz/devil-eye-lan-radar/internal/mitm"
	"github.com/antraz/devil-eye-lan-radar/internal/probe"
	"github.com/antraz/devil-eye-lan-radar/internal/scanner"
	"github.com/antraz/devil-eye-lan-radar/internal/sniffer"
	"github.com/antraz/devil-eye-lan-radar/internal/store"
)

//go:embed frontend
var frontendFS embed.FS

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, `
╔══════════════════════════════════════════════════════╗
║  LAN Radar requires root for ARP/raw socket access   ║
║  Run: sudo -E ./lan-radar                            ║
╚══════════════════════════════════════════════════════╝`)
		os.Exit(1)
	}

	st := store.New()
	hub := api.NewHub()
	lg := logger.New()
	hub.SetLogger(lg)
	go hub.RunBroadcastLoop()

	static, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatal("embed:", err)
	}

	sc, err := scanner.New(hub.Events, st)
	if err != nil {
		log.Fatal("scanner:", err)
	}
	hub.SetLabelStore(sc)
	// MITM manager
	var mitmMgr *mitm.MITM
	if sc.Iface() != nil && sc.Gateway() != nil {
		mitmMgr = mitm.New(sc.Iface(), sc.Gateway())
		// Pre-register devices after first scan cycle — done on demand via AddTarget
		// The MITM controller is registered with the hub so REST endpoints work
		hub.SetMITMController(&mitmWrapper{mgr: mitmMgr, sc: sc})
	}

	// DNS spoofer
	var dnsSpoofer *dnsspoof.Spoofer
	if sc.Iface() != nil {
		dnsSpoofer = dnsspoof.New(sc.Iface().Name)
		hub.SetDNSSpoofController(dnsSpoofer)
	}

	addr := "127.0.0.1:7777"
	if err := hub.Listen(addr, static); err != nil {
		log.Fatal("server:", err)
	}

	go sc.Run(15 * time.Second)

	if sc.Iface() != nil {
		snf := sniffer.New(sc.Iface(), hub.Events)
		go snf.Run()

		ps := probe.New(sc.Iface().Name, hub.Events)
		go ps.Run()
	}

	openChromium(fmt.Sprintf("http://%s", addr))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if mitmMgr != nil && mitmMgr.MITMActive() {
		mitmMgr.StopMITM()
	}
	if dnsSpoofer != nil && dnsSpoofer.Active() {
		dnsSpoofer.Stop()
	}
	log.Println("Shutdown.")
}

// mitmWrapper implements api.MITMController and registers all known
// LAN devices as targets when MITM is started.
type mitmWrapper struct {
	mgr *mitm.MITM
	sc  *scanner.Scanner
}

func (w *mitmWrapper) StartMITM() error {
	for ip, mac := range w.sc.Devices() {
		if w.sc.Gateway() != nil && ip == w.sc.Gateway().String() {
			continue
		}
		w.mgr.AddTarget(ip, mac)
	}
	return w.mgr.StartMITM()
}
func (w *mitmWrapper) StopMITM()                              { w.mgr.StopMITM() }
func (w *mitmWrapper) MITMActive() bool                       { return w.mgr.MITMActive() }
func (w *mitmWrapper) BlockDevice(ip string, mac net.HardwareAddr) { w.mgr.BlockDevice(ip, mac) }
func (w *mitmWrapper) UnblockDevice(ip string)                { w.mgr.UnblockDevice(ip) }
func (w *mitmWrapper) IsBlocked(ip string) bool               { return w.mgr.IsBlocked(ip) }
func (w *mitmWrapper) BlockedIPs() []string                   { return w.mgr.BlockedIPs() }

func openChromium(url string) {
	args := []string{
		"--app=" + url,
		"--window-size=1400,900",
		"--disable-background-networking",
		"--disable-sync",
		"--no-first-run",
		"--disable-default-apps",
		"--class=LanRadar",
		"--window-position=100,50",
	}
	sudoUser := os.Getenv("SUDO_USER")
	display := os.Getenv("DISPLAY")
	xauth := os.Getenv("XAUTHORITY")
	var cmd *exec.Cmd
	if sudoUser != "" {
		if display == "" {
			display = ":0"
		}
		shellCmd := fmt.Sprintf("DISPLAY=%s XAUTHORITY=%s chromium %s",
			display, xauth, strings.Join(args, " "))
		cmd = exec.Command("su", sudoUser, "-s", "/bin/sh", "-c", shellCmd)
	} else {
		cmd = exec.Command("chromium", args...)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Printf("Open %s manually (%v)", url, err)
	}
}
