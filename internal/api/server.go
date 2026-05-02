package api

import (
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

const trafficBufMax = 300

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type MITMController interface {
	StartMITM() error
	StopMITM()
	MITMActive() bool
}

type EventLogger interface {
	Log(ev Event)
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
	h.mu.RLock()
	defer h.mu.RUnlock()
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
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()
	h.sendFullState(conn)
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

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("LAN Radar listening on http://%s", ln.Addr())
	go http.Serve(ln, mux)
	return nil
}
