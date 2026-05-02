package store

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
)

const savePath = "data/store.json"

type DeviceMeta struct {
	Label    string               `json:"label,omitempty"`
	Country  string               `json:"country,omitempty"`
	Code     string               `json:"country_code,omitempty"`
	Timeline []api.TimelineEntry  `json:"timeline,omitempty"`
}

type data struct {
	Devices map[string]DeviceMeta `json:"devices"`
}

type Store struct {
	mu sync.RWMutex
	d  data
}

func New() *Store {
	s := &Store{d: data{Devices: make(map[string]DeviceMeta)}}
	s.load()
	go s.autoSave()
	return s
}

func (s *Store) GetMeta(ip string) DeviceMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.d.Devices[ip]
}

func (s *Store) SetLabel(ip, label string) {
	s.mu.Lock()
	m := s.d.Devices[ip]
	m.Label = label
	s.d.Devices[ip] = m
	s.mu.Unlock()
	s.save()
}

func (s *Store) SetGeo(ip, country, code string) {
	s.mu.Lock()
	m := s.d.Devices[ip]
	m.Country = country
	m.Code = code
	s.d.Devices[ip] = m
	s.mu.Unlock()
}

func (s *Store) RecordTimeline(ip, event string) {
	s.mu.Lock()
	m := s.d.Devices[ip]
	entry := api.TimelineEntry{Time: time.Now(), Event: event}
	m.Timeline = append(m.Timeline, entry)
	// Keep only last 50 events
	if len(m.Timeline) > 50 {
		m.Timeline = m.Timeline[len(m.Timeline)-50:]
	}
	s.d.Devices[ip] = m
	s.mu.Unlock()
}

func (s *Store) AllLabels() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string)
	for ip, m := range s.d.Devices {
		if m.Label != "" {
			out[ip] = m.Label
		}
	}
	return out
}

func (s *Store) load() {
	b, err := os.ReadFile(savePath)
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		log.Printf("store: load error: %v", err)
	}
	if s.d.Devices == nil {
		s.d.Devices = make(map[string]DeviceMeta)
	}
}

func (s *Store) save() {
	s.mu.RLock()
	b, err := json.MarshalIndent(s.d, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}
	os.MkdirAll("data", 0700)
	os.WriteFile(savePath, b, 0600)
}

func (s *Store) autoSave() {
	for range time.Tick(30 * time.Second) {
		s.save()
	}
}
