package geo

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Info struct {
	Country     string
	CountryCode string
	Flag        string
	Lat         float64
	Lon         float64
}

type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	info    Info
	expires time.Time
}

var c = &cache{entries: make(map[string]cacheEntry)}

// LookupCached returns geo info only if already in cache (no network call).
func LookupCached(ip string) Info {
	if isPrivate(net.ParseIP(ip)) {
		return Info{}
	}
	c.mu.RLock()
	entry, ok := c.entries[ip]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.info
	}
	return Info{}
}

// Lookup returns geo info for an IP. Private IPs return an empty Info.
// Uses ip-api.com (free, 45 req/min, no key needed).
func Lookup(ip string) Info {
	if isPrivate(net.ParseIP(ip)) {
		return Info{}
	}
	c.mu.RLock()
	entry, ok := c.entries[ip]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.info
	}

	info := fetch(ip)
	c.mu.Lock()
	c.entries[ip] = cacheEntry{info: info, expires: time.Now().Add(24 * time.Hour)}
	c.mu.Unlock()
	return info
}

func fetch(ip string) Info {
	url := "http://ip-api.com/json/?fields=country,countryCode,lat,lon"
	if ip != "" {
		url = fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode,lat,lon", ip)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return Info{}
	}
	defer resp.Body.Close()
	var data struct {
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return Info{}
	}
	return Info{
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Flag:        emojiFlag(data.CountryCode),
		Lat:         data.Lat,
		Lon:         data.Lon,
	}
}

// LookupSelf returns geo info for the server's own public IP.
func LookupSelf() Info {
	return fetch("")
}

// emojiFlag converts a 2-letter ISO 3166 country code to a flag emoji.
func emojiFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	// Regional Indicator base = 0x1F1E6 (for 'A')
	return string(rune(0x1F1E6+int(code[0]-'A'))) +
		string(rune(0x1F1E6+int(code[1]-'A')))
}

func isPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"}
	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return true
		}
	}
	return false
}
