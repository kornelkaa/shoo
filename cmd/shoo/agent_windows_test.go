package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"shoo/internal/winacl"
)

// TestSleeper isn't a test: the tests below start it as a process to stop.
func TestSleeper(t *testing.T) {
	if os.Getenv("SHOO_TEST_SLEEP") == "1" {
		time.Sleep(time.Minute)
	}
}

func alive(cmd *exec.Cmd) bool {
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
		return false
	case <-time.After(500 * time.Millisecond):
		return true
	}
}

// fakeDataDir points dataDir at a temporary folder.
func fakeDataDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("LocalAppData", base)
	dir := filepath.Join(base, "shoo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestKillProxyStopsShoo(t *testing.T) {
	dir := fakeDataDir(t)
	// The test binary is called shoo.test.exe, so it looks like shoo.
	cmd := exec.Command(os.Args[0], "-test.run=^TestSleeper$")
	cmd.Env = append(os.Environ(), "SHOO_TEST_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	os.WriteFile(filepath.Join(dir, pidFile), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	killProxy()
	if alive(cmd) {
		t.Error("the proxy is still running")
	}
	if fileExists(filepath.Join(dir, pidFile)) {
		t.Error("the number of a stopped process was kept")
	}
}

func TestKillProxyLeavesOtherProgramsAlone(t *testing.T) {
	dir := fakeDataDir(t)
	// As if Windows reused the process number for something else.
	cmd := exec.Command(system("ping.exe"), "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	os.WriteFile(filepath.Join(dir, pidFile), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	killProxy()
	if !alive(cmd) {
		t.Error("killed a process that isn't shoo")
	}
}

func TestShellExecuteInfoSize(t *testing.T) {
	want := map[uintptr]uintptr{8: 112, 4: 60}[unsafe.Sizeof(uintptr(0))]
	if got := unsafe.Sizeof(shellExecuteInfo{}); got != want {
		t.Errorf("size = %d, want %d as in the Windows headers", got, want)
	}
}

// TestTaskSchedulerAcceptsAgentXML really registers a task for a moment, so
// it only runs when asked: SHOO_TASK_TEST=1.
func TestTaskSchedulerAcceptsAgentXML(t *testing.T) {
	if os.Getenv("SHOO_TASK_TEST") != "1" {
		t.Skip("set SHOO_TASK_TEST=1 to try this with Task Scheduler")
	}
	sid, err := winacl.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	name := agentTask() + "-xml-test" // a name like the real one, with the SID in it
	dir := t.TempDir()
	for _, s := range []Settings{{Sites: "strict", StartAtLogin: true}, {Sites: sitesOff, StartAtLogin: false}} {
		f := filepath.Join(dir, "task.xml")
		// A program that exits at once: the triggers fire on registration.
		x := agentXML(system("whoami.exe"), "127.0.0.1:18899", filepath.Join(dir, "l.log"), sid, s)
		if err := os.WriteFile(f, utf16File(x), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := quiet("schtasks.exe", "/Create", "/TN", name, "/XML", f, "/F"); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		defer quiet("schtasks.exe", "/Delete", "/TN", name, "/F")
		// removeLegacyTask finds its own user's old task by this.
		out, err := exec.Command(system("schtasks.exe"), "/Query", "/TN", name, "/XML").Output()
		if err != nil || !strings.Contains(string(out), "<UserId>"+sid+"</UserId>") {
			t.Errorf("exported task doesn't name its user by SID: %v\n%s", err, out)
		}
		for _, flag := range []string{"/DISABLE", "/ENABLE"} {
			if err := quiet("schtasks.exe", "/Change", "/TN", name, flag); err != nil {
				t.Errorf("%s: %v", flag, err)
			}
		}
	}
}

// TestCleanupScriptRemovesRunningProgram runs uninstall's cleanup for real
// against a copy of this test program that is running from the folder.
func TestCleanupScriptRemovesRunningProgram(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Program Files O'Brien", "shoo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "shoo.exe")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(exe+".old", []byte("old"), 0o644)
	running := exec.Command(exe, "-test.run=^TestSleeper$")
	running.Env = append(os.Environ(), "SHOO_TEST_SLEEP=1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer running.Process.Kill()
	if os.Remove(exe) == nil {
		t.Fatal("Windows let a running program be deleted: this test proves nothing")
	}

	cleanup := exec.Command(system(`WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodePS(cleanupScript(exe, dir, []int{running.Process.Pid})))
	if err := cleanup.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if !fileExists(exe) {
		t.Fatal("deleted before the program exited")
	}
	running.Process.Kill()
	running.Wait()
	if err := cleanup.Wait(); err != nil {
		t.Fatal(err)
	}
	if fileExists(dir) {
		entries, _ := os.ReadDir(dir)
		t.Errorf("folder still there with %v", entries)
	}
}
