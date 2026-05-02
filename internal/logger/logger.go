package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/antraz/devil-eye-lan-radar/internal/api"
)

type Logger struct {
	mu   sync.Mutex
	file *os.File
	day  string
}

func New() *Logger {
	l := &Logger{}
	l.rotate(time.Now())
	return l
}

func (l *Logger) Log(ev api.Event) {
	switch ev.Type {
	case api.EventDeviceFound, api.EventDeviceLost, api.EventAlert, api.EventMITMStatus:
	default:
		return
	}
	now := time.Now()
	day := now.Format("2006-01-02")
	l.mu.Lock()
	defer l.mu.Unlock()
	if day != l.day {
		l.rotate(now)
	}
	if l.file == nil {
		return
	}
	entry := struct {
		Time time.Time     `json:"time"`
		Type api.EventType `json:"type"`
		IP   string        `json:"ip,omitempty"`
		Msg  string        `json:"msg,omitempty"`
	}{
		Time: now,
		Type: ev.Type,
	}
	if ev.Device != nil {
		entry.IP = ev.Device.IP
	}
	if ev.Alert != nil {
		entry.Msg = ev.Alert.Message
	}
	b, _ := json.Marshal(entry)
	l.file.Write(b)
	l.file.Write([]byte("\n"))
}

func (l *Logger) rotate(t time.Time) {
	if l.file != nil {
		l.file.Close()
	}
	l.day = t.Format("2006-01-02")
	os.MkdirAll("data/sessions", 0700)
	f, err := os.OpenFile(fmt.Sprintf("data/sessions/%s.jsonl", l.day), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	l.file = f
}
