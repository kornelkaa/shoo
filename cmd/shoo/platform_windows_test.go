package main

import (
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"shoo/internal/local"
	"shoo/internal/winnet"
)

func TestAgentXML(t *testing.T) {
	x := agentXML(`C:\Program Files\sh&oo\shoo.exe`, "127.0.0.1:8899", `C:\Users\me\shoo.log`, "S-1-5-21-1", Settings{Sites: "strict", StartAtLogin: true})
	var parsed struct {
		Triggers struct {
			Logon struct {
				UserID string `xml:"UserId"`
			} `xml:"LogonTrigger"`
		} `xml:"Triggers"`
		Actions struct {
			Exec struct {
				Command   string `xml:"Command"`
				Arguments string `xml:"Arguments"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	// The header says UTF-16, which is true of the file but not this string.
	d := xml.NewDecoder(strings.NewReader(strings.Replace(x, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	if err := d.Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Triggers.Logon.UserID != "S-1-5-21-1" {
		t.Errorf("logon trigger user = %q", parsed.Triggers.Logon.UserID)
	}
	if !strings.HasSuffix(strings.ToLower(parsed.Actions.Exec.Command), `\conhost.exe`) {
		t.Errorf("command = %q", parsed.Actions.Exec.Command)
	}
	want := `--headless "C:\Program Files\sh&oo\shoo.exe" run -addr 127.0.0.1:8899 -log C:\Users\me\shoo.log`
	if parsed.Actions.Exec.Arguments != want {
		t.Errorf("arguments = %q\nwant        %q", parsed.Actions.Exec.Arguments, want)
	}
	for _, s := range []string{"DisallowStartIfOnBatteries>false", "StopIfGoingOnBatteries>false", "<ExecutionTimeLimit>PT0S"} {
		if !strings.Contains(x, s) {
			t.Errorf("missing %q", s)
		}
	}
	if !strings.Contains(x, "<MultipleInstancesPolicy>IgnoreNew<") {
		t.Error("a second copy must not start while one runs")
	}
}

func TestAgentXMLChoices(t *testing.T) {
	x := agentXML(`C:\shoo.exe`, "127.0.0.1:8899", `C:\l.log`, "S-1-5-21-1", Settings{Sites: sitesOff, StartAtLogin: false})
	if !strings.Contains(x, "-sites=false") {
		t.Error("missing -sites=false")
	}
	if strings.Contains(x, "LogonTrigger") || strings.Contains(x, "Repetition") {
		t.Error("shouldn't start or restart by itself")
	}
}

func TestUTF16File(t *testing.T) {
	if got := utf16File("ab"); string(got) != "\xff\xfea\x00b\x00" {
		t.Errorf("got %q", got)
	}
}

func TestBeforeKey(t *testing.T) {
	if beforeKey("{a}", false) == beforeKey("{a}", true) {
		t.Error("IPv4 and IPv6 settings must be saved separately")
	}
}

func TestQuoteCommand(t *testing.T) {
	got := quoteCommand(`C:\Program Files\shoo\shoo-dns.exe`, "dns", "-data", `C:\Users\Me Too\shoo`)
	want := `"C:\Program Files\shoo\shoo-dns.exe" "dns" "-data" "C:\Users\Me Too\shoo"`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestProtectedBinary(t *testing.T) {
	if !protectedBinary(dnsBinary()) {
		t.Errorf("%s should count as protected", dnsBinary())
	}
	if protectedBinary(`C:\Users\me\shoo.exe`) {
		t.Error("a user folder shouldn't count as protected")
	}
}

func TestIsShooImage(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Program Files\shoo\shoo.exe`:  true,
		`C:\go\bin\shoo-debug.exe`:        true,
		`C:\Windows\System32\notepad.exe`: false,
	} {
		if got := isShooImage(path); got != want {
			t.Errorf("isShooImage(%q) = %v", path, got)
		}
	}
}

func TestAbsentShooInterfaces(t *testing.T) {
	present := []winnet.Adapter{{GUID: "{AAAA}"}}
	dns := map[string][]string{
		"{aaaa}": {"127.0.0.1"},      // present (other case): netsh handles it
		"{bbbb}": {"127.0.0.1"},      // switched off, still shoo: restore
		"{cccc}": {"192.168.1.1"},    // switched off, not shoo: leave alone
		"{dddd}": nil,                // automatic: leave alone
		"{eeee}": {"127.0.0.1", "x"}, // shoo plus more: not set by shoo
	}
	guids := []string{"{aaaa}", "{bbbb}", "{cccc}", "{dddd}", "{eeee}"}
	got := absentShooInterfaces(present, guids, false, func(g string) []string { return dns[g] })
	if !slices.Equal(got, []string{"{bbbb}"}) {
		t.Errorf("v4: got %v", got)
	}
	if got := absentShooInterfaces(nil, []string{"{ffff}"}, true, func(string) []string { return []string{"::1"} }); !slices.Equal(got, []string{"{ffff}"}) {
		t.Errorf("v6: got %v", got)
	}
}

func TestSavedDNS(t *testing.T) {
	before := map[string][]string{"{ABCD}": {"1.1.1.1"}, "{ABCD}#6": {"2606:4700::1111"}}
	if got := savedDNS(before, "{abcd}", false); !slices.Equal(got, []string{"1.1.1.1"}) {
		t.Errorf("v4 = %v", got)
	}
	if got := savedDNS(before, "{abcd}", true); !slices.Equal(got, []string{"2606:4700::1111"}) {
		t.Errorf("v6 = %v", got)
	}
	if got := savedDNS(before, "{other}", false); got != nil {
		t.Errorf("unknown = %v", got)
	}
}

func TestTaskDisabled(t *testing.T) {
	on := `<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Settings><Hidden>true</Hidden></Settings></Task>`
	off := `<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Settings><Enabled>false</Enabled></Settings></Task>`
	offTrigger := `<Task><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers><Settings></Settings></Task>`
	if taskDisabled(on) || !taskDisabled(off) || taskDisabled(offTrigger) {
		t.Error("wrong answer")
	}
	if !strings.Contains(agentXML(`C:\shoo.exe`, "127.0.0.1:8899", `C:\l.log`, "S-1", Settings{}), "<Priority>5</Priority>") {
		t.Error("task doesn't run at normal priority")
	}
}

func TestUserPort(t *testing.T) {
	for sid, want := range map[string]int{
		"S-1-5-21-111-222-333-1001": 1,
		"S-1-5-21-111-222-333-1002": 2,
		"S-1-5-21-111-222-333-500":  500,
		"bogus":                     0,
	} {
		if got := userPort(sid); got != want {
			t.Errorf("userPort(%s) = %d, want %d", sid, got, want)
		}
	}
	addr, err := chooseAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := local.RequireLoopback(addr); err != nil {
		t.Error(err)
	}
}

func TestPathWithout(t *testing.T) {
	path := `%SystemRoot%\system32;C:\Program Files\shoo;C:\Tools;c:\program files\SHOO\;`
	got, changed := pathWithout(path, `C:\Program Files\shoo`)
	if !changed || got != `%SystemRoot%\system32;C:\Tools;` {
		t.Errorf("got %q, %v", got, changed)
	}
	if _, changed := pathWithout(`C:\Tools`, `C:\Program Files\shoo`); changed {
		t.Error("changed a PATH without shoo")
	}
}

func TestDNSUserDirs(t *testing.T) {
	dirs := withDir(nil, `C:\Users\a\AppData\Local\shoo`)
	dirs = withDir(dirs, `c:\users\A\appdata\local\shoo`) // same folder
	dirs = withDir(dirs, `C:\Users\b\AppData\Local\shoo`)
	if len(dirs) != 2 {
		t.Fatalf("dirs = %v", dirs)
	}
	left := withoutDir(dirs, `C:\USERS\A\AppData\Local\shoo`)
	if !slices.Equal(left, []string{`C:\Users\b\AppData\Local\shoo`}) || len(dirs) != 2 {
		t.Errorf("left = %v, dirs = %v", left, dirs)
	}
}

func TestEncodePS(t *testing.T) {
	// powershell -EncodedCommand wants UTF-16LE, base64.
	if got := encodePS("hi"); got != "aABpAA==" {
		t.Errorf("got %s", got)
	}
}
