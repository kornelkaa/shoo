package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"shoo/internal/sites"
)

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	if s := loadSettings(dir); s.Sites != "strict" || !s.StartAtLogin {
		t.Errorf("defaults = %+v", s)
	}
	// An existing install keeps the level its list came from.
	os.WriteFile(filepath.Join(dir, "blocklist.txt"), []byte("# Source: "+strings.Join(sitesLevel("balanced"), "\n# Source: ")+"\nads.example.com\n"), 0o644)
	if s := loadSettings(dir); s.Sites != "balanced" {
		t.Errorf("level from list = %q", s.Sites)
	}
	if err := saveSettings(dir, Settings{Sites: sitesOff, StartAtLogin: false}); err != nil {
		t.Fatal(err)
	}
	if s := loadSettings(dir); s.Sites != sitesOff || s.StartAtLogin {
		t.Errorf("saved = %+v", s)
	}
	if (Settings{Sites: "bogus"}).valid() == nil {
		t.Error("bogus level accepted")
	}
}

func sitesLevel(name string) []string { return sites.Levels[name] }

func TestIsShooPAC(t *testing.T) {
	for url, want := range map[string]bool{
		"http://127.0.0.1:8899/proxy.pac":      true, // older shoo
		"http://127.0.0.1:8899/proxy.pac?v=1":  true,
		"http://127.0.0.1:8899/proxy.pac?v=2":  true,
		"http://127.0.0.1:18001/proxy.pac?v=2": true, // a per-user port
		"http://127.0.0.1:8899/proxy.pacx":     false,
		"http://192.168.1.5:8899/proxy.pac":    false,
		"http://corp.example/wpad.dat":         false,
		"https://127.0.0.1:8899/proxy.pac":     false,
	} {
		if got := isShooPAC(url); got != want {
			t.Errorf("isShooPAC(%q) = %v, want %v", url, got, want)
		}
	}
}

// TestCrasher isn't a test: TestCrashReachesLog starts it as a process.
func TestCrasher(t *testing.T) {
	if path := os.Getenv("SHOO_TEST_CRASH_LOG"); path != "" {
		if _, err := openLog(path); err != nil {
			t.Fatal(err)
		}
		panic("deliberate test crash")
	}
}

func TestCrashReachesLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shoo.log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrasher$")
	cmd.Env = append(os.Environ(), "SHOO_TEST_CRASH_LOG="+path)
	if cmd.Run() == nil {
		t.Fatal("the process should have crashed")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "deliberate test crash") {
		t.Errorf("the log doesn't have the crash report:\n%s", b)
	}
}

func TestOpenLogRotatesBigLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shoo.log")
	if err := os.WriteFile(path, make([]byte, maxLogBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	// openLog hands the file to the runtime for crash reports, which keeps
	// it open: let go of it, or Windows can't delete the test folder.
	debug.SetCrashOutput(nil, debug.CrashOptions{})
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Errorf("new log: %v, %v", fi, err)
	}
	if fi, err := os.Stat(path + ".old"); err != nil || fi.Size() != maxLogBytes+1 {
		t.Errorf("old log: %v, %v", fi, err)
	}
}

func TestDNSBlocksForSeveralUsers(t *testing.T) {
	strict := sites.NewList([]string{"ads.example.com", "tracker.example.net"}, nil)
	relaxed := sites.NewList([]string{"ads.example.com"}, []string{"tracker.example.net"})
	for name, want := range map[string]bool{
		"ads.example.com":     true,  // everyone blocks it
		"tracker.example.net": false, // one user allowed it: a site broke
		"www.example.org":     false,
	} {
		if got := dnsBlocks([]*sites.List{strict, relaxed}, name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if !dnsBlocks([]*sites.List{strict}, "tracker.example.net") {
		t.Error("one user: their own list")
	}
}
