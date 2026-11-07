// Package stats counts what shoo blocked, by hour, kind and site, and keeps
// the counts in a small JSON file so they survive restarts.
//
// Only blocked ad and tracker sites are counted, never the pages you visit,
// and only for the last Keep days.
package stats

import (
	"encoding/json"
	"errors"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Kinds of blocked things.
const (
	Domain  = "domain"  // a request to an ad domain (proxy)
	Script  = "script"  // an ad or tracking script, blocked by URL
	Image   = "image"   // an ad image or tracking pixel, blocked by URL
	Other   = "other"   // anything else blocked by URL (fetch, frames, ...)
	YouTube = "youtube" // a YouTube response with its ad fields removed
	DNS     = "dns"     // an ad domain lookup answered by the DNS server
)

// Kinds lists every kind in display order.
var Kinds = []string{Domain, Script, Image, Other, YouTube, DNS}

// Files the proxy and the DNS server keep their counts in. They're separate
// processes, so each writes only its own file.
const (
	ProxyFile = "stats.json"
	DNSFile   = "stats-dns.json"
)

const (
	// Keep is how many days of hourly and per-site counts are kept.
	Keep = 31
	// maxSitesPerDay caps the per-site counts of one day; later sites
	// still count in the totals.
	maxSitesPerDay = 1000
)

// Data is what a stats file holds.
type Data struct {
	Since time.Time        `json:"since"`
	Total map[string]int64 `json:"total"` // kind -> count, all time
	// Hours: the Unix time an hour starts -> kind -> count.
	Hours map[int64]map[string]int64 `json:"hours"`
	// Days: local date ("2006-01-02") -> blocked site -> count.
	Days map[string]map[string]int64 `json:"days"`
}

func newData(now time.Time) Data {
	return Data{
		Since: now,
		Total: map[string]int64{},
		Hours: map[int64]map[string]int64{},
		Days:  map[string]map[string]int64{},
	}
}

// Recorder counts blocks in memory and saves them to its file.
type Recorder struct {
	Log *log.Logger

	path string
	now  func() time.Time

	mu    sync.Mutex
	d     Data
	dirty bool
}

// Open loads the stats file at path. A missing or unreadable file starts
// the counts over.
func Open(path string, logger *log.Logger) *Recorder {
	r := &Recorder{Log: logger, path: path, now: time.Now}
	d, err := Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Printf("stats file unreadable, starting over: %v", err)
	}
	if err != nil {
		d = newData(r.now())
	}
	r.d = d
	return r
}

// Load reads a stats file.
func Load(path string) (Data, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Data{}, err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return Data{}, err
	}
	if d.Total == nil {
		d.Total = map[string]int64{}
	}
	if d.Hours == nil {
		d.Hours = map[int64]map[string]int64{}
	}
	if d.Days == nil {
		d.Days = map[string]map[string]int64{}
	}
	return d, nil
}

// Add counts one blocked request of kind to host (host may be "").
func (r *Recorder) Add(kind, host string) {
	if r == nil {
		return
	}
	now := r.now()
	hour := now.Truncate(time.Hour).Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.d.Total[kind]++
	h := r.d.Hours[hour]
	if h == nil {
		h = map[string]int64{}
		r.d.Hours[hour] = h
		r.prune(now)
	}
	h[kind]++
	if site := Site(host); site != "" {
		day := now.Format(time.DateOnly)
		m := r.d.Days[day]
		if m == nil {
			m = map[string]int64{}
			r.d.Days[day] = m
		}
		if _, ok := m[site]; ok || len(m) < maxSitesPerDay {
			m[site]++
		}
	}
	r.dirty = true
}

// prune drops hours and days older than Keep days. r.mu is held.
func (r *Recorder) prune(now time.Time) {
	cut := now.AddDate(0, 0, -Keep)
	for h := range r.d.Hours {
		if h < cut.Unix() {
			delete(r.d.Hours, h)
		}
	}
	cutDay := cut.Format(time.DateOnly)
	for d := range r.d.Days {
		if d < cutDay {
			delete(r.d.Days, d)
		}
	}
}

// Snapshot returns a copy of the counts.
func (r *Recorder) Snapshot() Data {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Merge(r.d)
}

// Save writes the counts to the file if they changed.
func (r *Recorder) Save() error {
	r.mu.Lock()
	if !r.dirty {
		r.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(r.d)
	r.dirty = false
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return writeFileAtomic(r.path, b)
}

// Run saves the counts every interval, forever.
func (r *Recorder) Run(every time.Duration) {
	for range time.Tick(every) {
		if err := r.Save(); err != nil && r.Log != nil {
			r.Log.Printf("saving stats: %v", err)
		}
	}
}

func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stats-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) // CreateTemp makes it 0600
}

// Site is the site a host belongs to (ads.example.co.uk -> example.co.uk).
func Site(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return s
	}
	return host
}

// Merge adds up several stats (e.g. the proxy's and the DNS server's) into
// a new Data.
func Merge(ds ...Data) Data {
	out := newData(time.Time{})
	for _, d := range ds {
		if !d.Since.IsZero() && (out.Since.IsZero() || d.Since.Before(out.Since)) {
			out.Since = d.Since
		}
		for k, n := range d.Total {
			out.Total[k] += n
		}
		for h, m := range d.Hours {
			o := out.Hours[h]
			if o == nil {
				o = map[string]int64{}
				out.Hours[h] = o
			}
			for k, n := range m {
				o[k] += n
			}
		}
		for day, m := range d.Days {
			o := out.Days[day]
			if o == nil {
				o = map[string]int64{}
				out.Days[day] = o
			}
			for s, n := range m {
				o[s] += n
			}
		}
	}
	return out
}

// Sum is the count in [from, to) per kind.
func (d Data) Sum(from, to time.Time) map[string]int64 {
	out := map[string]int64{}
	for h, m := range d.Hours {
		if t := time.Unix(h, 0); !t.Before(from) && t.Before(to) {
			for k, n := range m {
				out[k] += n
			}
		}
	}
	return out
}

// Count is the total of all kinds in m.
func Count(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// LastHours is the total of each of the last n hours, oldest first; the
// last one is the hour now is in.
func (d Data) LastHours(now time.Time, n int) []int64 {
	out := make([]int64, n)
	cur := now.Truncate(time.Hour)
	for i := range n {
		out[n-1-i] = Count(d.Hours[cur.Add(-time.Duration(i)*time.Hour).Unix()])
	}
	return out
}

// Day is one local calendar day's total.
type Day struct {
	Date  time.Time
	Count int64
}

// LastDays is the total of each of the last n local days, oldest first;
// the last one is today.
func (d Data) LastDays(now time.Time, n int) []Day {
	byDay := map[string]int64{}
	for h, m := range d.Hours {
		byDay[time.Unix(h, 0).In(now.Location()).Format(time.DateOnly)] += Count(m)
	}
	today := StartOfDay(now)
	out := make([]Day, n)
	for i := range n {
		day := today.AddDate(0, 0, -(n - 1 - i))
		out[i] = Day{Date: day, Count: byDay[day.Format(time.DateOnly)]}
	}
	return out
}

// StartOfDay is midnight (local) of t's day.
func StartOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// SiteCount is one row of Top.
type SiteCount struct {
	Site  string
	Count int64
}

// Top is the n most blocked sites over the last days days (today
// included), most blocked first.
func (d Data) Top(now time.Time, days, n int) []SiteCount {
	sum := map[string]int64{}
	first := StartOfDay(now).AddDate(0, 0, -(days - 1)).Format(time.DateOnly)
	for day, m := range d.Days {
		if day >= first {
			for s, c := range m {
				sum[s] += c
			}
		}
	}
	out := make([]SiteCount, 0, len(sum))
	for _, s := range slices.Sorted(maps.Keys(sum)) {
		out = append(out, SiteCount{s, sum[s]})
	}
	slices.SortStableFunc(out, func(a, b SiteCount) int {
		switch {
		case a.Count > b.Count:
			return -1
		case a.Count < b.Count:
			return 1
		}
		return 0
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
