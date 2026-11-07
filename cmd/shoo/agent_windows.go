package main

// The scheduled task that keeps the proxy running in the background and
// starts it at login. Unlike a service it runs as the user, who owns the
// certificate's key, and needs no admin rights to install.

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"shoo/internal/winacl"
)

const pidFile = "shoo.pid"

// legacyTask is the task older versions made. Task names are shared by
// everyone on the PC, so a single name only worked for one user.
const legacyTask = "shoo"

// agentTask is this user's task: "shoo-" and their account's SID.
func agentTask() string {
	sid, err := winacl.CurrentUser()
	if err != nil {
		return legacyTask
	}
	return legacyTask + "-" + sid
}

// removeLegacyTask stops and deletes the task older versions made, if it
// runs as this user. Another user's isn't visible to us, and stays.
func removeLegacyTask() {
	sid, err := winacl.CurrentUser()
	if err != nil {
		return
	}
	out, err := exec.Command(system("schtasks.exe"), "/Query", "/TN", legacyTask, "/XML").Output()
	if err != nil || !strings.Contains(string(out), "<UserId>"+sid+"</UserId>") {
		return
	}
	quiet("schtasks.exe", "/Change", "/TN", legacyTask, "/DISABLE")
	quiet("schtasks.exe", "/End", "/TN", legacyTask)
	killProxy()
	quiet("schtasks.exe", "/Delete", "/TN", legacyTask, "/F")
}

func logPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "shoo.log"), nil
}

// agentXML is the task definition. conhost runs shoo without a window, which
// a program built for the terminal would otherwise open. Task Scheduler has
// no KeepAlive: with StartAtLogin, a trigger every minute starts shoo again
// if it stopped, and does nothing while it's running (IgnoreNew). Priority 5
// is normal: Task Scheduler's default (7) runs the proxy below normal
// programs, which slows every web request while the computer is busy.
func agentXML(bin, addr, logFile, userSID string, s Settings) string {
	e := html.EscapeString
	args := []string{"--headless", bin, "run", "-addr", addr, "-log", logFile}
	if s.Sites == sitesOff {
		args = append(args, "-sites=false")
	}
	for i, a := range args {
		args[i] = syscall.EscapeArg(a)
	}
	triggers := "<Triggers />"
	if s.StartAtLogin {
		repeat := `<Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>`
		triggers = `<Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>` + e(userSID) + `</UserId>` + repeat + `</LogonTrigger>
    <RegistrationTrigger><Enabled>true</Enabled>` + repeat + `</RegistrationTrigger>
  </Triggers>`
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Blocks ads: shoo's local proxy.</Description></RegistrationInfo>
  ` + triggers + `
  <Principals>
    <Principal id="Author">
      <UserId>` + e(userSID) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + e(system("conhost.exe")) + `</Command>
      <Arguments>` + e(strings.Join(args, " ")) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// notePID remembers the running proxy, for killProxy.
func notePID(dir string) {
	os.WriteFile(filepath.Join(dir, pidFile), []byte(strconv.Itoa(os.Getpid())), 0o644)
}

// killProxy stops the proxy notePID remembered, after checking that the
// process is still shoo: Windows reuses process numbers.
func killProxy() {
	dir, err := dataDir()
	if err != nil {
		return
	}
	file := filepath.Join(dir, pidFile)
	defer os.Remove(file)
	b, err := os.ReadFile(file)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid == os.Getpid() {
		return
	}
	const access = windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
		return
	}
	if !isShooImage(windows.UTF16ToString(buf[:size])) {
		return
	}
	if windows.TerminateProcess(h, 0) == nil {
		windows.WaitForSingleObject(h, 3000)
	}
}

func isShooImage(path string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Base(path)), "shoo")
}

// agentLoaded reports whether the task exists and is switched on (`shoo stop`
// switches it off). The task's XML is checked because schtasks' other output
// depends on the system's language.
func agentLoaded() bool {
	out, err := exec.Command(system("schtasks.exe"), "/Query", "/TN", agentTask(), "/XML").Output()
	return err == nil && !taskDisabled(string(out))
}

// taskDisabled reports whether a task definition is switched off. Only its
// Settings say so; triggers have Enabled elements of their own.
func taskDisabled(xml string) bool {
	_, settings, _ := strings.Cut(xml, "<Settings>")
	settings, _, _ = strings.Cut(settings, "</Settings>")
	return strings.Contains(settings, "<Enabled>false</Enabled>")
}

// agentInstalled reports whether the task exists, switched on or not.
func agentInstalled() bool { return quiet("schtasks.exe", "/Query", "/TN", agentTask()) == nil }

func installAgent(exe, addr, pacURL string, s Settings) error {
	logFile, err := logPath()
	if err != nil {
		return err
	}
	if !agentInstalled() && proxyAnswers(pacURL) {
		return errors.New("shoo is already running in a terminal window: stop it with Ctrl+C, then run `shoo setup` again")
	}
	if err := os.MkdirAll(filepath.Dir(logFile), 0o700); err != nil {
		return err
	}
	sid, err := winacl.CurrentUser()
	if err != nil {
		return err
	}
	// Task Scheduler wants the file in UTF-16, as the XML header says.
	f, err := os.CreateTemp("", "shoo-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(utf16File(agentXML(exe, addr, logFile, sid, s)))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	// Stop the running copy so a changed binary or address takes effect.
	stopAgent()
	removeLegacyTask()
	if err := quiet("schtasks.exe", "/Create", "/TN", agentTask(), "/XML", f.Name(), "/F"); err != nil {
		return fmt.Errorf("creating the background service: %w", err)
	}
	if err := startAgent(); err != nil {
		return err
	}
	return waitForProxy(pacURL, logFile)
}

func utf16File(s string) []byte {
	units := append([]uint16{0xfeff}, utf16.Encode([]rune(s))...)
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// startAgent starts the background service now (it must be installed).
func startAgent() error {
	if err := quiet("schtasks.exe", "/Run", "/TN", agentTask()); err != nil {
		return fmt.Errorf("starting the background service: %w (run `shoo setup` first)", err)
	}
	return nil
}

// loadAgent turns the installed task back on after `shoo stop`.
func loadAgent() error {
	if !agentInstalled() {
		return errors.New("shoo isn't set up yet: run `shoo setup`")
	}
	if err := quiet("schtasks.exe", "/Change", "/TN", agentTask(), "/ENABLE"); err != nil {
		return fmt.Errorf("loading the background service: %w", err)
	}
	return nil
}

// stopAgent stops the background service. The task is switched off first, or
// its trigger would start shoo again within a minute. Ending the task only
// ends conhost, so shoo itself has to be stopped too.
func stopAgent() {
	if !agentInstalled() {
		return
	}
	quiet("schtasks.exe", "/Change", "/TN", agentTask(), "/DISABLE")
	quiet("schtasks.exe", "/End", "/TN", agentTask())
	killProxy()
}

// removeAgent stops the background service and deletes it.
func removeAgent() error {
	removeLegacyTask()
	if !agentInstalled() {
		return nil
	}
	stopAgent()
	if err := quiet("schtasks.exe", "/Delete", "/TN", agentTask(), "/F"); err != nil {
		return fmt.Errorf("remove the task: %w", err)
	}
	return nil
}
