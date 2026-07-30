package traefik_hermes_guard

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"sync"
)

type geoipEntry struct {
	Net     *net.IPNet
	Country string
}

type geoipDB struct {
	mu      sync.RWMutex
	entries []geoipEntry
	loaded  bool
}

func newGeoIPDB(path string) (*geoipDB, error) {
	db := &geoipDB{}
	if path == "" {
		return db, nil
	}
	if err := db.load(path); err != nil {
		return db, err
	}
	return db, nil
}

func (db *geoipDB) load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var raw struct {
		Version  int    `json:"version"`
		Networks []struct {
			CIDR    string `json:"cidr"`
			Country string `json:"country"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	db.entries = make([]geoipEntry, 0, len(raw.Networks))
	for _, n := range raw.Networks {
		_, ipNet, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			continue
		}
		db.entries = append(db.entries, geoipEntry{
			Net:     ipNet,
			Country: n.Country,
		})
	}

	sort.Slice(db.entries, func(i, j int) bool {
		onesI, _ := db.entries[i].Net.Mask.Size()
		onesJ, _ := db.entries[j].Net.Mask.Size()
		return onesI > onesJ
	})

	db.loaded = true
	return nil
}

func (db *geoipDB) Lookup(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, e := range db.entries {
		if e.Net.Contains(ip) {
			return e.Country
		}
	}
	return ""
}

func (db *geoipDB) IsLoaded() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.loaded
}
