package main

// `shoo stats`: charts of what shoo blocked, drawn with Unicode blocks.
// Colors adapt to light and dark terminals, and are left out when the
// output isn't a terminal (or NO_COLOR is set).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"shoo/internal/sites"
	"shoo/internal/stats"
)

const viewWidth = 67

type color = lipgloss.AdaptiveColor

var (
	cText2 = color{Light: "#52514e", Dark: "#c3c2b7"}
	cMuted = color{Light: "#8b8a86", Dark: "#7d7c77"}
	cGrid  = color{Light: "#dcdbd6", Dark: "#3a3a37"}
	cBar   = color{Light: "#2a78d6", Dark: "#3987e5"}
	cNow   = color{Light: "#86b6ef", Dark: "#256abf"} // the hour still in progress
	// heat is the blue ramp for the calendar, from few to many blocks.
	heat = []color{
		{Light: "#b7d3f6", Dark: "#184f95"},
		{Light: "#86b6ef", Dark: "#256abf"},
		{Light: "#5598e7", Dark: "#3987e5"},
		{Light: "#256abf", Dark: "#6da7ec"},
		{Light: "#104281", Dark: "#b7d3f6"},
	}
	// Each kind keeps its color everywhere (the order is checked for
	// color blindness).
	kindColor = map[string]color{
		stats.Domain:  {Light: "#2a78d6", Dark: "#3987e5"},
		stats.Script:  {Light: "#eb6834", Dark: "#d95926"},
		stats.Image:   {Light: "#1baf7a", Dark: "#199e70"},
		stats.Other:   {Light: "#eda100", Dark: "#c98500"},
		stats.YouTube: {Light: "#e87ba4", Dark: "#d55181"},
		stats.DNS:     {Light: "#008300", Dark: "#008300"},
	}
	kindLabel = map[string]string{
		stats.Domain:  "Ad domains",
		stats.Script:  "Ad scripts",
		stats.Image:   "Images & pixels",
		stats.Other:   "Other requests",
		stats.YouTube: "YouTube ads",
		stats.DNS:     "DNS (other apps)",
	}
)

func fg(c color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

var (
	bold  = lipgloss.NewStyle().Bold(true)
	muted = fg(cMuted)
	text2 = fg(cText2)
)

func showStats(dir, addr string) error {
	fmt.Print(renderStats(loadStats(dir, addr), time.Now()))
	return nil
}

// loadStats adds up the proxy's counts (live if it's running, else its
// file) and the DNS server's file.
func loadStats(dir, addr string) stats.Data {
	var proxy stats.Data
	c := http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get("http://" + addr + "/stats"); err == nil {
		var st sites.Stats
		if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&st) == nil && st.History != nil {
			proxy = *st.History
		}
		resp.Body.Close()
	}
	if proxy.Total == nil {
		proxy, _ = stats.Load(filepath.Join(dir, stats.ProxyFile))
	}
	dns, _ := stats.Load(filepath.Join(dir, stats.DNSFile))
	return stats.Merge(proxy, dns)
}

func renderStats(d stats.Data, now time.Time) string {
	var b strings.Builder
	title := bold.Render("shoo") + muted.Render(" · what was blocked")
	date := muted.Render(now.Format("Mon 2 Jan, 15:04"))
	b.WriteString("\n" + spread(title, date, viewWidth) + "\n\n")
	b.WriteString(tiles(d, now) + "\n")
	if stats.Count(d.Total) == 0 {
		b.WriteString("\n" + text2.Render("  Nothing blocked yet. Counting starts when the proxy runs this") +
			"\n" + text2.Render("  version of shoo: browse a little, then look again.") + "\n\n")
		return b.String()
	}
	b.WriteString("\n" + section("Last 24 hours", "per hour") + "\n")
	b.WriteString(hoursChart(d.LastHours(now, 24), now) + "\n")
	b.WriteString("\n" + section("Last 30 days", "per day") + "\n")
	b.WriteString(calendar(d.LastDays(now, 35), now) + "\n")
	week := d.Sum(stats.StartOfDay(now).AddDate(0, 0, -6), now.Add(time.Hour))
	b.WriteString("\n" + section("By type", "last 7 days") + "\n")
	b.WriteString(byType(week) + "\n")
	if top := d.Top(now, 7, 10); len(top) > 0 {
		b.WriteString("\n" + section("Most blocked sites", "last 7 days") + "\n")
		b.WriteString(topSites(top) + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

// tiles are the four headline numbers.
func tiles(d stats.Data, now time.Time) string {
	today := stats.StartOfDay(now)
	end := now.Add(time.Hour)
	nToday := stats.Count(d.Sum(today, end))
	// Yesterday up to the same time of day, so the comparison is fair.
	nYday := stats.Count(d.Sum(today.AddDate(0, 0, -1), now.Add(-24*time.Hour).Add(time.Hour)))
	n7 := stats.Count(d.Sum(today.AddDate(0, 0, -6), end))
	n30 := stats.Count(d.Sum(today.AddDate(0, 0, -29), end))
	all := stats.Count(d.Total)

	var vs string
	switch {
	case nYday == 0:
		vs = "so far today"
	case nToday >= nYday:
		vs = fmt.Sprintf("▲%d%% vs yday", pct(nToday-nYday, nYday))
	default:
		vs = fmt.Sprintf("▼%d%% vs yday", pct(nYday-nToday, nYday))
	}
	since := "all time"
	if !d.Since.IsZero() {
		since = "since " + d.Since.Format("2 Jan")
	}
	return lipgloss.JoinHorizontal(lipgloss.Top,
		tile("TODAY", nToday, vs), " ",
		tile("7 DAYS", n7, "≈ "+short(n7/7)+" a day"), " ",
		tile("30 DAYS", n30, "≈ "+short(n30/30)+" a day"), " ",
		tile("ALL TIME", all, since),
	)
}

func tile(label string, n int64, sub string) string {
	body := muted.Render(label) + "\n" +
		bold.Render(comma(n)) + "\n" +
		text2.Render(sub)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cGrid).
		Padding(0, 1).
		Width(14). // 16 with the border: four tiles fill viewWidth
		Render(body)
}

// section is a heading followed by a rule to the right edge.
func section(title, note string) string {
	left := bold.Render(title) + " "
	right := " " + muted.Render(note)
	fill := viewWidth - lipgloss.Width(left) - lipgloss.Width(right)
	return left + fg(cGrid).Render(strings.Repeat("─", max(fill, 1))) + right
}

var vBlocks = []string{" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}

// hoursChart is a column chart of the last 24 hours, the last column being
// the current hour.
func hoursChart(hours []int64, now time.Time) string {
	const height = 7
	top := niceMax(maxOf(hours))
	labels := map[int]string{height - 1: short(top), (height - 1) / 2: short(top / 2)}
	var b strings.Builder
	for row := height - 1; row >= 0; row-- {
		b.WriteString(muted.Render(fmt.Sprintf("%6s ", labels[row])))
		_, gridRow := labels[row]
		for i, v := range hours {
			eighths := int(v * height * 8 / max(top, 1))
			if v > 0 && eighths == 0 {
				eighths = 1
			}
			cell := eighths - row*8
			c := cBar
			if i == len(hours)-1 {
				c = cNow
			}
			switch {
			case cell >= 8:
				b.WriteString(fg(c).Render("█"))
			case cell > 0:
				b.WriteString(fg(c).Render(vBlocks[cell]))
			case gridRow:
				b.WriteString(fg(cGrid).Render("┈"))
			default:
				b.WriteString(" ")
			}
			if i < len(hours)-1 {
				if gridRow {
					b.WriteString(fg(cGrid).Render("┈"))
				} else {
					b.WriteString(" ")
				}
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat(" ", 7) + fg(cGrid).Render(strings.Repeat("─", 2*len(hours)-1)) + "\n")

	// Hour labels every 6 hours, and "now" under the last column.
	axis := []rune(strings.Repeat(" ", 2*len(hours)+3))
	first := now.Truncate(time.Hour).Add(-time.Duration(len(hours)-1) * time.Hour)
	for i := range len(hours) - 2 {
		if h := first.Add(time.Duration(i) * time.Hour).Hour(); h%6 == 0 {
			copy(axis[2*i:], []rune(fmt.Sprintf("%02d", h)))
		}
	}
	copy(axis[2*(len(hours)-1)-1:], []rune("now"))
	b.WriteString(strings.Repeat(" ", 7) + muted.Render(strings.TrimRight(string(axis), " ")))

	// The busiest hour, on one line under the axis.
	peak, at := int64(0), 0
	for i, v := range hours {
		if v > peak {
			peak, at = v, i
		}
	}
	if peak > 0 {
		t := first.Add(time.Duration(at) * time.Hour)
		b.WriteString("\n" + strings.Repeat(" ", 7) + text2.Render(fmt.Sprintf("busiest hour %s–%s · %s blocked", t.Format("15:04"), t.Add(time.Hour).Format("15:04"), comma(peak))))
	}
	return b.String()
}

// calendar is a heatmap of the last 5 weeks (Monday to Sunday) with a few
// numbers beside it.
func calendar(days []stats.Day, now time.Time) string {
	today := stats.StartOfDay(now)
	byDate := map[string]int64{}
	for _, d := range days {
		byDate[d.Date.Format(time.DateOnly)] = d.Count
	}
	// Five columns of weeks, the last one holding today.
	monday := today.AddDate(0, 0, -((int(today.Weekday()) + 6) % 7))
	start := monday.AddDate(0, 0, -28)
	const weeks = 5

	var hi int64
	for _, d := range days {
		hi = max(hi, d.Count)
	}

	var g strings.Builder
	// Month names above the week where a month starts.
	g.WriteString("    ")
	prev := -1
	for w := range weeks {
		m := start.AddDate(0, 0, 7*w+6).Month() // the week's Sunday
		if int(m) != prev {
			g.WriteString(muted.Render(m.String()[:3]))
		} else {
			g.WriteString("   ")
		}
		prev = int(m)
	}
	g.WriteString("\n")
	names := []string{"Mon", "", "Wed", "", "Fri", "", "Sun"}
	for row := range 7 {
		g.WriteString(muted.Render(fmt.Sprintf("%-3s ", names[row])))
		for w := range weeks {
			day := start.AddDate(0, 0, 7*w+row)
			n := byDate[day.Format(time.DateOnly)]
			switch {
			case day.After(today):
				g.WriteString("  ")
			case n == 0:
				g.WriteString(fg(cGrid).Render("··"))
			default:
				lvl := int((n*int64(len(heat)) - 1) / hi)
				g.WriteString(fg(heat[lvl]).Render("██"))
			}
			if w < weeks-1 {
				g.WriteString(" ")
			}
		}
		g.WriteString("\n")
	}
	g.WriteString(muted.Render("    less "))
	for _, c := range heat {
		g.WriteString(fg(c).Render("█"))
	}
	g.WriteString(muted.Render(" more"))

	// Beside it: the busiest and quietest day, and the average, over the
	// last 30 days.
	last := days[len(days)-30:]
	var busiest, quietest stats.Day
	var total int64
	quietest.Count = -1
	for _, d := range last[:len(last)-1] { // today isn't over yet
		total += d.Count
		if d.Count > busiest.Count {
			busiest = d
		}
		if d.Count > 0 && (quietest.Count < 0 || d.Count < quietest.Count) {
			quietest = d
		}
	}
	total += last[len(last)-1].Count
	var side strings.Builder
	side.WriteString("\n")
	line := func(label, value string) {
		side.WriteString(muted.Render(fmt.Sprintf("%-15s", label)) + value + "\n")
	}
	line("Total", bold.Render(comma(total)))
	line("Daily average", text2.Render(comma(total/30)))
	if busiest.Count > 0 {
		line("Busiest day", text2.Render(busiest.Date.Format("Mon 2 Jan")+" · "+comma(busiest.Count)))
	}
	if quietest.Count > 0 {
		line("Quietest day", text2.Render(quietest.Date.Format("Mon 2 Jan")+" · "+comma(quietest.Count)))
	}
	line("Today so far", text2.Render(comma(last[len(last)-1].Count)))
	return lipgloss.JoinHorizontal(lipgloss.Top, g.String(), "      ", side.String())
}

var hBlocks = []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}

// hbar is a horizontal bar of v out of hi, at most width cells, padded to
// width.
func hbar(v, hi int64, width int, c color) string {
	eighths := int(v * int64(width) * 8 / max(hi, 1))
	if v > 0 && eighths == 0 {
		eighths = 1
	}
	s := strings.Repeat("█", eighths/8) + hBlocks[eighths%8]
	return fg(c).Render(s) + strings.Repeat(" ", width-lipgloss.Width(s))
}

// byType is one stacked bar of the whole week, then a row per kind.
func byType(m map[string]int64) string {
	total := stats.Count(m)
	var b strings.Builder
	if total == 0 {
		return text2.Render("  nothing blocked in the last 7 days")
	}
	// The stacked bar: each kind's share of viewWidth cells, rounded so
	// the cells add up (largest remainder first).
	const w = viewWidth
	cells := map[string]int{}
	used := 0
	type rem struct {
		kind string
		r    int64
	}
	var rems []rem
	for _, k := range stats.Kinds {
		cells[k] = int(m[k] * w / total)
		used += cells[k]
		rems = append(rems, rem{k, m[k] * w % total})
	}
	for used < w {
		best := 0
		for i := range rems {
			if rems[i].r > rems[best].r {
				best = i
			}
		}
		cells[rems[best].kind]++
		rems[best].r = -1
		used++
	}
	for _, k := range stats.Kinds {
		b.WriteString(fg(kindColor[k]).Render(strings.Repeat("▆", cells[k])))
	}
	b.WriteString("\n\n")

	var hi int64
	for _, k := range stats.Kinds {
		hi = max(hi, m[k])
	}
	for _, k := range stats.Kinds {
		b.WriteString(fg(kindColor[k]).Render("■") + " ")
		b.WriteString(fmt.Sprintf("%-17s", kindLabel[k]))
		b.WriteString(hbar(m[k], hi, 26, kindColor[k]))
		if m[k] == 0 {
			b.WriteString(muted.Render(fmt.Sprintf(" %10s %5s", "0", "")))
		} else {
			b.WriteString(fmt.Sprintf(" %10s", comma(m[k])) + muted.Render(fmt.Sprintf(" %4d%%", pct(m[k], total))))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func topSites(top []stats.SiteCount) string {
	var b strings.Builder
	hi := top[0].Count
	for i, s := range top {
		name := s.Site
		if len(name) > 24 {
			name = name[:23] + "…"
		}
		b.WriteString(muted.Render(fmt.Sprintf("%3d  ", i+1)))
		b.WriteString(fmt.Sprintf("%-25s", name))
		b.WriteString(hbar(s.Count, hi, 26, cBar))
		b.WriteString(fmt.Sprintf(" %8s", comma(s.Count)))
		if i < len(top)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// statsSummary is the one line `shoo status` shows.
func statsSummary(d stats.Data, now time.Time) string {
	today := stats.StartOfDay(now)
	end := now.Add(time.Hour)
	return fmt.Sprintf("%s blocked today, %s in the last 7 days (charts: `shoo stats`)",
		comma(stats.Count(d.Sum(today, end))), comma(stats.Count(d.Sum(today.AddDate(0, 0, -6), end))))
}

// spread puts left and right at the two ends of a width-wide line.
func spread(left, right string, width int) string {
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	return left + strings.Repeat(" ", max(gap, 1)) + right
}

func maxOf(vs []int64) int64 {
	var m int64
	for _, v := range vs {
		m = max(m, v)
	}
	return m
}

// niceMax rounds v up to a round number (1, 1.5, 2, 2.5, 3, 4, 5, 6 or 8
// times a power of ten), so the axis labels are round.
func niceMax(v int64) int64 {
	if v <= 0 {
		return 1
	}
	for p := int64(1); ; p *= 10 {
		for _, m := range []int64{10, 15, 20, 25, 30, 40, 50, 60, 80} {
			if n := m * p / 10; n >= v && n > 0 {
				return n
			}
		}
	}
}

func pct(part, whole int64) int64 {
	if whole == 0 {
		return 0
	}
	return (part*100 + whole/2) / whole
}

// comma writes n with thousands separators: 12345 -> "12,345".
func comma(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + comma(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// short writes n compactly: 950, 4.4k, 12k, 1.2M.
func short(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprint(n)
	case n < 10_000:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/1000), ".0") + "k"
	case n < 1_000_000:
		return fmt.Sprintf("%dk", (n+500)/1000)
	default:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/1e6), ".0") + "M"
	}
}
