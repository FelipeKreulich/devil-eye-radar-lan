package api

import (
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/antraz/devil-eye-lan-radar/internal/geo"
	"github.com/gorilla/websocket"
)

const trafficBufMax = 300

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type MITMController interface {
	StartMITM() error
	StopMITM()
	MITMActive() bool
	BlockDevice(ip string, mac net.HardwareAddr)
	UnblockDevice(ip string)
	IsBlocked(ip string) bool
	BlockedIPs() []string
}

type EventLogger interface {
	Log(ev Event)
}

type LabelSetter interface {
	SetLabel(ip, label string)
}

type DNSSpoofController interface {
	Start() error
	Stop()
	Active() bool
	AddRule(domain, ip string)
	RemoveRule(domain string)
	Rules() map[string]string
}

type Hub struct {
	mu          sync.RWMutex
	clients     map[*websocket.Conn]bool
	devices     map[string]*Device
	Events      chan Event
	trafficMu  sync.RWMutex
	trafficBuf []TrafficEvent
	mitmCtrl   MITMController
	logger     EventLogger
	dnsSpoof   DNSSpoofController
	labelStore LabelSetter
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*websocket.Conn]bool),
		devices:    make(map[string]*Device),
		Events:     make(chan Event, 512),
		trafficBuf: make([]TrafficEvent, 0, trafficBufMax),
	}
}

func (h *Hub) SetMITMController(m MITMController) { h.mitmCtrl = m }

func (h *Hub) SetLogger(l EventLogger) { h.logger = l }

func (h *Hub) SetDNSSpoofController(d DNSSpoofController) { h.dnsSpoof = d }

func (h *Hub) SetLabelStore(ls LabelSetter) { h.labelStore = ls }

func (h *Hub) Broadcast(e Event) {
	h.mu.Lock()
	switch e.Type {
	case EventDeviceFound, EventDeviceUpdated:
		if e.Device != nil {
			h.devices[e.Device.IP] = e.Device
		}
	case EventDeviceLost:
		if e.Device != nil {
			if d, ok := h.devices[e.Device.IP]; ok {
				d.Active = false
			}
		}
	}
	h.mu.Unlock()

	if e.Type == EventTraffic && e.Traffic != nil {
		h.trafficMu.Lock()
		h.trafficBuf = append(h.trafficBuf, *e.Traffic)
		if len(h.trafficBuf) > trafficBufMax {
			h.trafficBuf = h.trafficBuf[1:]
		}
		h.trafficMu.Unlock()
	}

	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	if h.logger != nil {
		h.logger.Log(e)
	}
	// Use full Lock (not RLock) to serialize WebSocket writes — gorilla/websocket
	// is not safe for concurrent writes on the same connection.
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		c.WriteMessage(websocket.TextMessage, data)
	}
}

func (h *Hub) sendFullState(c *websocket.Conn) {
	h.mu.RLock()
	list := make([]Device, 0, len(h.devices))
	for _, d := range h.devices {
		list = append(list, *d)
	}
	h.mu.RUnlock()

	h.trafficMu.RLock()
	traffic := make([]TrafficEvent, len(h.trafficBuf))
	copy(traffic, h.trafficBuf)
	h.trafficMu.RUnlock()

	mitmOn := h.mitmCtrl != nil && h.mitmCtrl.MITMActive()
	data, _ := json.Marshal(Event{Type: EventFullState, Devices: list, Traffics: traffic, MITMOn: &mitmOn})
	c.WriteMessage(websocket.TextMessage, data)
}

func (h *Hub) RunBroadcastLoop() {
	for e := range h.Events {
		h.Broadcast(e)
	}
}

func (h *Hub) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade:", err)
		return
	}
	// Send full state before adding to the broadcast list to avoid a
	// concurrent-write race between sendFullState and Broadcast.
	h.sendFullState(conn)
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	h.mu.Lock()
	delete(h.clients, conn)
	h.mu.Unlock()
	conn.Close()
}

func (h *Hub) Listen(addr string, staticFS fs.FS) error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/ws", h.wsHandler)

	mux.HandleFunc("/api/geo/me", func(w http.ResponseWriter, r *http.Request) {
		info := geo.LookupSelf()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"lat":     info.Lat,
			"lon":     info.Lon,
			"country": info.Country,
			"cc":      info.CountryCode,
		})
	})

	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		list := make([]Device, 0, len(h.devices))
		for _, d := range h.devices {
			list = append(list, *d)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/mitm/on", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		if h.mitmCtrl == nil {
			http.Error(w, "MITM not available", 503)
			return
		}
		if err := h.mitmCtrl.StartMITM(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		on := true
		h.Events <- Event{Type: EventMITMStatus, MITMOn: &on}
		h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{
			Level:   "danger",
			Message: "MITM ACTIVE — interceptando todo o tráfego LAN",
		}}
		w.WriteHeader(204)
	})

	mux.HandleFunc("/api/mitm/off", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		if h.mitmCtrl != nil {
			h.mitmCtrl.StopMITM()
		}
		off := false
		h.Events <- Event{Type: EventMITMStatus, MITMOn: &off}
		h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{
			Level:   "info",
			Message: "MITM desativado — ARP restaurado",
		}}
		w.WriteHeader(204)
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		list := make([]Device, 0, len(h.devices))
		for _, d := range h.devices {
			list = append(list, *d)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=lan-radar-export.json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(list)
	})

	// Sessions API
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		entries, err := os.ReadDir("data/sessions")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		var dates []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				dates = append(dates, strings.TrimSuffix(e.Name(), ".jsonl"))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dates)
	})

	mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		date := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
		if date == "" || strings.Contains(date, "/") || strings.Contains(date, "..") {
			http.Error(w, "invalid", 400)
			return
		}
		path := "data/sessions/" + date + ".jsonl"
		http.ServeFile(w, r, path)
	})

	// Block endpoints
	mux.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var blocked []string
			if h.mitmCtrl != nil {
				blocked = h.mitmCtrl.BlockedIPs()
			}
			if blocked == nil {
				blocked = []string{}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(blocked)
		case http.MethodPost:
			if h.mitmCtrl == nil {
				http.Error(w, "MITM not available", 503)
				return
			}
			var body struct {
				IP  string `json:"ip"`
				MAC string `json:"mac"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
				http.Error(w, "bad request", 400)
				return
			}
			mac, err := net.ParseMAC(body.MAC)
			if err != nil {
				http.Error(w, "invalid mac", 400)
				return
			}
			h.mitmCtrl.BlockDevice(body.IP, mac)
			h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{
				Level:   "danger",
				Message: "BLOCKED: " + body.IP + " isolado da rede",
				IP:      body.IP,
			}}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "use GET or POST", 405)
		}
	})

	mux.HandleFunc("/api/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		if h.mitmCtrl == nil {
			http.Error(w, "MITM not available", 503)
			return
		}
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			http.Error(w, "bad request", 400)
			return
		}
		h.mitmCtrl.UnblockDevice(body.IP)
		h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{
			Level:   "info",
			Message: "UNBLOCKED: " + body.IP + " restaurado",
			IP:      body.IP,
		}}
		w.WriteHeader(http.StatusNoContent)
	})

	// Label endpoint: POST /api/label {ip, label}
	mux.HandleFunc("/api/label", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		var body struct {
			IP    string `json:"ip"`
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			http.Error(w, "bad request", 400)
			return
		}
		if h.labelStore != nil {
			h.labelStore.SetLabel(body.IP, body.Label)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// DNS spoof endpoints
	mux.HandleFunc("/api/dnsspoof/status", func(w http.ResponseWriter, r *http.Request) {
		active := h.dnsSpoof != nil && h.dnsSpoof.Active()
		rules := map[string]string{}
		if h.dnsSpoof != nil {
			rules = h.dnsSpoof.Rules()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"active": active, "rules": rules})
	})

	mux.HandleFunc("/api/dnsspoof/on", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		if h.dnsSpoof == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		h.dnsSpoof.Start()
		h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{Level: "warning", Message: "DNS SPOOF ativo — redirecionando DNS da LAN"}}
		w.WriteHeader(204)
	})

	mux.HandleFunc("/api/dnsspoof/off", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", 405)
			return
		}
		if h.dnsSpoof != nil {
			h.dnsSpoof.Stop()
		}
		h.Events <- Event{Type: EventAlert, Alert: &AlertEvent{Level: "info", Message: "DNS SPOOF desativado"}}
		w.WriteHeader(204)
	})

	mux.HandleFunc("/api/dnsspoof/rules", func(w http.ResponseWriter, r *http.Request) {
		if h.dnsSpoof == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			h.dnsSpoof.AddRule(body.Domain, body.IP)
			w.WriteHeader(204)
		case http.MethodDelete:
			var body struct {
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			h.dnsSpoof.RemoveRule(body.Domain)
			w.WriteHeader(204)
		default:
			http.Error(w, "use POST or DELETE", 405)
		}
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("LAN Radar listening on http://%s", ln.Addr())
	go http.Serve(ln, mux)
	return nil
}
