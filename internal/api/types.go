package api

import "time"

type Service struct {
	Port   int    `json:"port"`
	Name   string `json:"name"`
	Banner string `json:"banner,omitempty"`
}

type TimelineEntry struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"` // "online" | "offline"
}

type Device struct {
	IP          string         `json:"ip"`
	MAC         string         `json:"mac"`
	Hostname    string         `json:"hostname"`
	Vendor      string         `json:"vendor"`
	OS          string         `json:"os"`
	TTL         int            `json:"ttl"`
	OpenPorts   []Service      `json:"open_ports"`
	IsGateway   bool           `json:"is_gateway"`
	Active      bool           `json:"active"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Label       string         `json:"label,omitempty"`
	Country     string         `json:"country,omitempty"`
	CountryCode string         `json:"country_code,omitempty"`
	BytesIn     int64          `json:"bytes_in"`
	BytesOut    int64          `json:"bytes_out"`
	RateIn      float64        `json:"rate_in"`
	RateOut     float64        `json:"rate_out"`
	Timeline    []TimelineEntry `json:"timeline,omitempty"`
	PingHistory []int           `json:"ping_history,omitempty"`
}

type TrafficEvent struct {
	Time      time.Time `json:"time"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Proto     string    `json:"proto"`
	Domain    string    `json:"domain,omitempty"`
	Details   string    `json:"details,omitempty"`
	Country   string    `json:"country,omitempty"`
	Flag      string    `json:"flag,omitempty"`
	Threat    bool      `json:"threat"`
	ThreatMsg string    `json:"threat_msg,omitempty"`
}

type BandwidthStat struct {
	IP      string  `json:"ip"`
	RateIn  float64 `json:"rate_in"`
	RateOut float64 `json:"rate_out"`
}

type AlertEvent struct {
	Level   string `json:"level"` // "info" | "warning" | "danger"
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
}

type EventType string

const (
	EventDeviceFound   EventType = "device_found"
	EventDeviceUpdated EventType = "device_updated"
	EventDeviceLost    EventType = "device_lost"
	EventFullState     EventType = "full_state"
	EventScanStart     EventType = "scan_start"
	EventScanEnd       EventType = "scan_end"
	EventTraffic       EventType = "traffic"
	EventBandwidth     EventType = "bandwidth"
	EventAlert         EventType = "alert"
	EventMITMStatus    EventType = "mitm_status"
	EventProbeDevice   EventType = "probe_device"
	EventPassiveOS     EventType = "passive_os"
)

type OSHint struct {
	IP string `json:"ip"`
	OS string `json:"os"`
}

type Event struct {
	Type      EventType      `json:"type"`
	Device    *Device        `json:"device,omitempty"`
	Devices   []Device       `json:"devices,omitempty"`
	Traffic   *TrafficEvent  `json:"traffic,omitempty"`
	Traffics  []TrafficEvent `json:"traffics,omitempty"`
	Bandwidth []BandwidthStat `json:"bandwidth,omitempty"`
	Alert     *AlertEvent    `json:"alert,omitempty"`
	MITMOn    *bool          `json:"mitm_on,omitempty"`
	OSHints   []OSHint       `json:"os_hints,omitempty"`
}
