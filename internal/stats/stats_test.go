package stats

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), ProxyFile)
	now := time.Date(2026, 11, 7, 14, 30, 0, 0, time.Local)
	r := Open(path, nil)
	r.now = func() time.Time { return now }

	r.Add(Domain, "ads.doubleclick.net")
	r.Add(Domain, "doubleclick.net")
	r.Add(Script, "www.google-analytics.com")
	r.Add(YouTube, "")
	now = now.Add(-25 * time.Hour) // yesterday
	r.Add(Image, "pixel.facebook.com")
	now = now.Add(25 * time.Hour)

	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	today := StartOfDay(now)
	if got := Count(d.Sum(today, now.Add(time.Hour))); got != 4 {
		t.Errorf("today = %d, want 4", got)
	}
	if got := d.Total[Domain]; got != 2 {
		t.Errorf("total domains = %d, want 2", got)
	}
	hours := d.LastHours(now, 24)
	if hours[23] != 4 || hours[22] != 0 {
		t.Errorf("last hours end with %v, want [... 0 4]", hours[20:])
	}
	days := d.LastDays(now, 3)
	if days[2].Count != 4 || days[1].Count != 1 || days[0].Count != 0 {
		t.Errorf("last days = %v", days)
	}
	top := d.Top(now, 1, 10)
	if len(top) != 2 || top[0] != (SiteCount{"doubleclick.net", 2}) {
		t.Errorf("top today = %v", top)
	}
	if top := d.Top(now, 2, 10); len(top) != 3 {
		t.Errorf("top over 2 days = %v, want 3 sites", top)
	}
}

func TestPrune(t *testing.T) {
	now := time.Date(2026, 11, 7, 14, 0, 0, 0, time.Local)
	r := Open(filepath.Join(t.TempDir(), ProxyFile), nil)
	r.now = func() time.Time { return now.AddDate(0, 0, -40) }
	r.Add(Domain, "old.example")
	r.now = func() time.Time { return now }
	r.Add(Domain, "new.example")
	d := r.Snapshot()
	if len(d.Hours) != 1 || len(d.Days) != 1 {
		t.Errorf("old counts kept: %d hours, %d days", len(d.Hours), len(d.Days))
	}
	if d.Total[Domain] != 2 {
		t.Errorf("all-time total = %d, want 2", d.Total[Domain])
	}
}

func TestMerge(t *testing.T) {
	t1 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	a := Data{Since: t1.Add(time.Hour), Total: map[string]int64{Domain: 2}, Hours: map[int64]map[string]int64{1: {Domain: 2}}, Days: map[string]map[string]int64{"2026-11-01": {"a.com": 2}}}
	b := Data{Since: t1, Total: map[string]int64{DNS: 3}, Hours: map[int64]map[string]int64{1: {DNS: 3}}, Days: map[string]map[string]int64{"2026-11-01": {"a.com": 1}}}
	m := Merge(a, b)
	if !m.Since.Equal(t1) || Count(m.Total) != 5 || Count(m.Hours[1]) != 5 || m.Days["2026-11-01"]["a.com"] != 3 {
		t.Errorf("merge = %+v", m)
	}
	if a.Hours[1][DNS] != 0 {
		t.Error("merge changed its input")
	}
}

func TestSite(t *testing.T) {
	for host, want := range map[string]string{
		"ads.doubleclick.net": "doubleclick.net", "x.y.example.co.uk.": "example.co.uk",
		"Localhost": "localhost", "": "",
	} {
		if got := Site(host); got != want {
			t.Errorf("Site(%q) = %q, want %q", host, got, want)
		}
	}
}
