package main

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"shoo/internal/stats"
)

// sampleStats is 30 days of made-up blocks, busier in the daytime.
func sampleStats(now time.Time) stats.Data {
	r := rand.New(rand.NewPCG(1, 2))
	d := stats.Data{
		Since: now.AddDate(0, 0, -30),
		Total: map[string]int64{},
		Hours: map[int64]map[string]int64{},
		Days:  map[string]map[string]int64{},
	}
	sites := []string{"doubleclick.net", "google-analytics.com", "googlesyndication.com", "facebook.net", "criteo.com", "amazon-adsystem.com", "scorecardresearch.com", "taboola.com", "hotjar.com", "adnxs.com", "rubiconproject.com"}
	weights := map[string]int64{stats.Domain: 60, stats.Script: 22, stats.Image: 12, stats.Other: 5, stats.YouTube: 1, stats.DNS: 3}
	for h := now.Truncate(time.Hour).AddDate(0, 0, -30); !h.After(now); h = h.Add(time.Hour) {
		busy := int64(0)
		if hr := h.Hour(); hr >= 8 && hr <= 23 {
			busy = int64(r.IntN(200) + 40)
		} else if r.IntN(4) == 0 {
			busy = int64(r.IntN(20))
		}
		m := map[string]int64{}
		for k, w := range weights {
			m[k] = busy * w / 100
			d.Total[k] += m[k]
		}
		d.Hours[h.Unix()] = m
		day := h.Format(time.DateOnly)
		if d.Days[day] == nil {
			d.Days[day] = map[string]int64{}
		}
		for i, s := range sites {
			d.Days[day][s] += busy / int64(i+2)
		}
	}
	return d
}

func TestRenderStatsWidth(t *testing.T) {
	now := time.Date(2026, 11, 7, 14, 32, 0, 0, time.Local)
	for _, d := range []stats.Data{sampleStats(now), {}} {
		out := renderStats(d, now)
		for _, line := range strings.Split(out, "\n") {
			if w := lipgloss.Width(line); w > viewWidth {
				t.Errorf("line %d wide (max %d): %q", w, viewWidth, line)
			}
		}
		if testing.Verbose() {
			t.Log("\n" + out)
		}
	}
}

func TestComma(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -4500: "-4,500"} {
		if got := comma(n); got != want {
			t.Errorf("comma(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestNiceMax(t *testing.T) {
	for v, want := range map[int64]int64{0: 1, 1: 1, 3: 3, 7: 8, 240: 250, 251: 300, 999: 1000, 1001: 1500} {
		if got := niceMax(v); got != want {
			t.Errorf("niceMax(%d) = %d, want %d", v, got, want)
		}
	}
}
