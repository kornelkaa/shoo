package main

// Removing shoo itself at the end of `shoo uninstall`: the program in
// %ProgramFiles%\shoo and its PATH entry, which install.ps1 added. It runs
// in the same admin step as removing the DNS service, so it asks nothing
// more.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"shoo/internal/certs"
)

const environmentKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// installedExe is where install.ps1 puts shoo.
func installedExe() string { return filepath.Join(systemDir(), "shoo.exe") }

// programInstalled reports whether there's anything for removeProgram to do.
func programInstalled() bool {
	if fileExists(installedExe()) {
		return true
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, environmentKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	path, _, _ := k.GetStringValue("Path")
	_, changed := pathWithout(path, systemDir())
	return changed
}

// removeProgram (admin) is uninstall's admin step: it removes the DNS
// service for the user whose folder is dir (if dns), then shoo itself, unless
// someone else on the PC still uses it. parent is the `shoo uninstall`
// process, which is still running from the file being removed.
func removeProgram(dir string, dns bool, parent int) error {
	if !isAdmin() {
		return errors.New("needs admin rights: run `shoo uninstall`")
	}
	if dns && dnsServes(dir) {
		// If this failed, shoo is still needed to try again.
		if err := disableDNS(dir); err != nil {
			return err
		}
	}
	if otherShooUsers(dir) {
		fmt.Println("  shoo stays installed: other people on this PC use it")
		return nil
	}
	removed, err := removeFromPath(systemDir())
	if err != nil {
		return fmt.Errorf("removing shoo from PATH: %w", err)
	}
	if removed {
		fmt.Printf("  %-24s removed from PATH\n", systemDir())
	}
	if fileExists(installedExe()) {
		if err := removeWhenDone(parent); err != nil {
			return fmt.Errorf("removing %s: %w", installedExe(), err)
		}
		fmt.Printf("  %-24s removed when this window's shoo finishes\n", installedExe())
	}
	return nil
}

// otherShooUsers reports whether another account on the PC has shoo set up:
// a certificate in its shoo folder, or a place in the DNS service's list.
func otherShooUsers(dir string) bool {
	if users, _ := readDNSUsers(); len(withoutDir(users, dir)) > 0 {
		return true
	}
	const profiles = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profiles, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	for _, sid := range sids {
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		home, _, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err != nil {
			continue
		}
		if home, err = registry.ExpandString(home); err != nil {
			continue
		}
		theirs := filepath.Join(home, "AppData", "Local", "shoo")
		if !strings.EqualFold(filepath.Clean(theirs), filepath.Clean(dir)) && fileExists(filepath.Join(theirs, certs.CertFile)) {
			return true
		}
	}
	return false
}

// pathWithout removes dir from a PATH value, keeping everything else as it
// was written (including names like %SystemRoot%).
func pathWithout(path, dir string) (string, bool) {
	want := strings.TrimRight(dir, `\`)
	var keep []string
	changed := false
	for _, p := range strings.Split(path, ";") {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(p), `\`), want) {
			changed = true
			continue
		}
		keep = append(keep, p)
	}
	return strings.Join(keep, ";"), changed
}

// removeFromPath takes dir out of the machine PATH. It reports whether it
// was there.
func removeFromPath(dir string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, environmentKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	// GetStringValue doesn't expand %SystemRoot% and the like, so they're
	// written back unchanged.
	path, typ, err := k.GetStringValue("Path")
	if err != nil {
		return false, err
	}
	newPath, changed := pathWithout(path, dir)
	if !changed {
		return false, nil
	}
	if typ == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", newPath)
	} else {
		err = k.SetStringValue("Path", newPath)
	}
	if err != nil {
		return false, err
	}
	environmentChanged()
	return true, nil
}

// environmentChanged tells running programs (Explorer, new terminals) that
// the PATH changed.
func environmentChanged() {
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x1a, 0x2
	env, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	procSendMsgTimeout.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}

var procSendMsgTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// removeWhenDone deletes shoo's program folder once parent and this process
// have exited: Windows doesn't let a running program's file be deleted. A
// hidden PowerShell does it, with this process's admin rights. Only the
// files install.ps1 makes go, and the folder only if that leaves it empty.
func removeWhenDone(parent int) error {
	script := cleanupScript(installedExe(), systemDir(), []int{parent, os.Getpid()})
	cmd := exec.Command(system(`WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
		"-EncodedCommand", encodePS(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// cleanupScript waits for pids to exit, then deletes exe (and the .old and
// .new copies install.ps1 may leave), then dir if that leaves it empty.
func cleanupScript(exe, dir string, pids []int) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var b strings.Builder
	for _, pid := range pids {
		if pid > 0 {
			fmt.Fprintf(&b, "Wait-Process -Id %d -ErrorAction SilentlyContinue\n", pid)
		}
	}
	fmt.Fprintf(&b, `$files = %s, %s, %s
for ($i = 0; $i -lt 30; $i++) {
    $files | ForEach-Object { Remove-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue }
    if (-not (Test-Path -LiteralPath $files[0])) { break }
    Start-Sleep -Seconds 1
}
try { [IO.Directory]::Delete(%s) } catch {}
`, q(exe), q(exe+".old"), q(exe+".new"), q(dir))
	return b.String()
}

// encodePS encodes a script for powershell -EncodedCommand (UTF-16, base64).
func encodePS(script string) string {
	units := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}
