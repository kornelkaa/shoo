package main

// The Windows side of DNS blocking. Windows has no privileged ports, so the
// server needs no admin rights at any point: it's a service running as the
// low-privilege LocalService account, which can read shoo's lists (granted
// by enableDNS) but not the certificate's key. Installing it and changing
// adapters' DNS does need admin rights.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"shoo/internal/winacl"
	"shoo/internal/winnet"
)

const (
	dnsService     = "shoo-dns"
	dnsAddr6       = "[::1]:53"
	dnsServerIP6   = "::1"
	localService   = `NT AUTHORITY\LocalService`
	maxDNSLogBytes = 1 << 20
)

// dnsExtraAddrs: Windows keeps separate IPv4 and IPv6 DNS settings, and an
// adapter left with its IPv6 servers would ask them about ad domains.
var dnsExtraAddrs = []string{dnsAddr6}

// systemDir holds admin-only files: a copy of shoo for the service (so it
// never runs a file the user account can change), and the DNS settings from
// before shoo. It's found through Windows, not %ProgramFiles%, which the
// caller of an admin process could have changed.
func systemDir() string {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "shoo")
}

func dnsBinary() string  { return filepath.Join(systemDir(), "shoo-dns.exe") }
func dnsLogFile() string { return filepath.Join(systemDir(), "shoo-dns.log") }

// dnsInstalled reports whether the DNS service has been installed.
func dnsInstalled() bool { return fileExists(dnsBinary()) }

// dnsPrivileges has nothing to do: the service already has few rights.
func dnsPrivileges(string) (func() error, error) {
	return func() error { return nil }, nil
}

// dnsUsersFile lists the shoo folders of everyone on the PC who uses the
// DNS service, as JSON. It's in systemDir, so only an admin can change it.
const dnsUsersFile = "dns-users.json"

// readDNSUsers returns the folders the DNS service blocks for. legacy is
// set when an older version installed the service, which had no list: it
// served one user, named on its command line.
func readDNSUsers() (dirs []string, legacy bool) {
	b, err := os.ReadFile(filepath.Join(systemDir(), dnsUsersFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, dnsInstalled()
	}
	json.Unmarshal(b, &dirs)
	return dirs, false
}

func writeDNSUsers(dirs []string) error {
	b, _ := json.MarshalIndent(dirs, "", "  ")
	path := filepath.Join(systemDir(), dnsUsersFile)
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// withDir and withoutDir add or remove a folder; Windows paths ignore case.
func withDir(dirs []string, dir string) []string {
	if slices.ContainsFunc(dirs, func(d string) bool { return strings.EqualFold(d, dir) }) {
		return dirs
	}
	return append(dirs, dir)
}

func withoutDir(dirs []string, dir string) []string {
	return slices.DeleteFunc(slices.Clone(dirs), func(d string) bool { return strings.EqualFold(d, dir) })
}

// dnsServes reports whether the DNS service blocks for the user whose shoo
// folder is dir.
func dnsServes(dir string) bool {
	dirs, legacy := readDNSUsers()
	return legacy || slices.ContainsFunc(dirs, func(d string) bool { return strings.EqualFold(d, dir) })
}

// dnsMain is `shoo dns`: the service, which blocks for every user in
// dnsUsersFile, or the server in a terminal for testing (-data DIR).
func dnsMain(dir string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		if dir == "" {
			return errors.New("run `shoo dns -data DIR` with a shoo folder")
		}
		return runDNS([]string{dir}, os.Stderr)
	}
	dirs, _ := readDNSUsers()
	if len(dirs) == 0 && dir != "" {
		dirs = []string{dir} // installed by an older version
	}
	if fi, err := os.Stat(dnsLogFile()); err == nil && fi.Size() > maxDNSLogBytes {
		os.Truncate(dnsLogFile(), 0)
	}
	f, err := os.OpenFile(dnsLogFile(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	// A service has no terminal: crash reports go to the log too.
	debug.SetCrashOutput(f, debug.CrashOptions{})
	logger := log.New(f, "shoo-dns: ", log.LstdFlags)
	return svc.Run(dnsService, &dnsHandler{dirs: dirs, logger: logger})
}

type dnsHandler struct {
	dirs   []string
	logger *log.Logger
}

// Execute reports the service's state to Windows while the server runs.
func (h *dnsHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- runDNS(h.dirs, h.logger.Writer()) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			// A failure exit code makes Windows restart the service.
			h.logger.Printf("stopped: %v", err)
			return true, 1
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

// beforeKey names an adapter's saved DNS servers. The GUID stays the same
// when an adapter is renamed.
func beforeKey(guid string, v6 bool) string {
	if v6 {
		return guid + "#6"
	}
	return guid
}

func shooDNS(v6 bool) []string {
	if v6 {
		return []string{dnsServerIP6}
	}
	return []string{dnsServerIP}
}

func usesShooDNS(a winnet.Adapter, v6 bool) bool {
	return slices.Equal(winnet.StaticDNS(a.GUID, v6), shooDNS(v6))
}

// dnsEverywhere reports whether every adapter uses shoo's DNS.
func dnsEverywhere() bool {
	adapters, err := managedAdapters()
	if err != nil || len(adapters) == 0 {
		return false
	}
	v6 := dnsAnswersAt(dnsAddr6)
	for _, a := range adapters {
		if !usesShooDNS(a, false) || (v6 && !usesShooDNS(a, true)) {
			return false
		}
	}
	return true
}

// dnsInstalledFrom reports whether the service runs the same shoo as exe.
func dnsInstalledFrom(exe string) bool {
	if !dnsInstalled() {
		return false
	}
	a, err1 := fileHash(exe)
	b, err2 := fileHash(dnsBinary())
	return err1 == nil && err2 == nil && a == b
}

// setAdapterDNS changes one adapter's DNS servers. Empty means automatic.
func setAdapterDNS(a winnet.Adapter, v6 bool, servers []string) error {
	family, name := "ipv4", fmt.Sprintf("name=%d", a.Index)
	if v6 {
		family = "ipv6"
	}
	if len(servers) == 0 {
		return quiet("netsh.exe", "interface", family, "set", "dnsservers", name, "source=dhcp")
	}
	if err := quiet("netsh.exe", "interface", family, "set", "dnsservers", name, "source=static",
		"address="+servers[0], "validate=no"); err != nil {
		return err
	}
	for i, s := range servers[1:] {
		if err := quiet("netsh.exe", "interface", family, "add", "dnsservers", name,
			"address="+s, fmt.Sprintf("index=%d", i+2), "validate=no"); err != nil {
			return err
		}
	}
	return nil
}

// flushDNSCache makes Windows forget addresses it looked up earlier, so ad
// domains it already knew are looked up again.
func flushDNSCache() { quiet("ipconfig.exe", "/flushdns") }

// stopDNSService stops the service if it's running and waits for that.
func stopDNSService(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	s.Control(svc.Stop)
	for i := 0; i < 40; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// restartDNSService restarts the service, so it reads dnsUsersFile again.
func restartDNSService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(dnsService)
	if err != nil {
		return err
	}
	defer s.Close()
	stopDNSService(s)
	if err := s.Start(); err != nil {
		return fmt.Errorf("restarting the DNS service: %w", err)
	}
	return nil
}

// installBinary copies exe to the admin-only folder. The service is stopped,
// but its file can stay locked for a moment after that.
func installBinary(exe string) error {
	src, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	tmp := dnsBinary() + ".new"
	if err := os.WriteFile(tmp, src, 0o755); err != nil {
		return err
	}
	for i := 0; ; i++ {
		err = os.Rename(tmp, dnsBinary())
		if err == nil || i == 20 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// installDNSService installs or updates the service and starts it.
func installDNSService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(dnsService)
	exists := err == nil
	if exists {
		defer s.Close()
		stopDNSService(s)
	}
	if err := installBinary(exe); err != nil {
		return err
	}
	if !exists {
		s, err = m.CreateService(dnsService, dnsBinary(), mgr.Config{
			DisplayName:      "shoo DNS",
			Description:      "Blocks ad domains for shoo. Stopping it stops name lookups while Windows is pointed at it: use shoo disable.",
			StartType:        mgr.StartAutomatic,
			ServiceStartName: localService,
		}, "dns")
		if err != nil {
			return err
		}
		defer s.Close()
	} else {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		// mgr has no helper for this: it's how CreateService builds it.
		// The folders are in dnsUsersFile, not on the command line.
		cfg.BinaryPathName = quoteCommand(dnsBinary(), "dns")
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	}
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 2 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	return s.Start()
}

func quoteCommand(args ...string) string {
	for i, a := range args {
		args[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
	}
	return strings.Join(args, " ")
}

// enableDNS (admin) installs the DNS service and points every adapter's DNS
// at it. It only switches DNS once the server answers.
func enableDNS(exe, dir string) error {
	if !isAdmin() {
		return errors.New("needs admin rights: run `shoo enable -dns -data DIR`")
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s isn't a full path", dir)
	}
	account, err := winacl.LocalService()
	if err != nil {
		return err
	}
	if err := winacl.Grant(dir, account, winacl.Read); err != nil {
		return err
	}
	if err := os.MkdirAll(systemDir(), 0o755); err != nil {
		return err
	}
	// The service can write its log and nothing else in this folder.
	f, err := os.OpenFile(dnsLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	f.Close()
	if err := winacl.Grant(dnsLogFile(), account, winacl.Write); err != nil {
		return err
	}
	// Before the service (re)starts, so it reads this user's lists too.
	users, _ := readDNSUsers()
	if err := writeDNSUsers(withDir(users, dir)); err != nil {
		return err
	}
	if err := installDNSService(exe); err != nil {
		return fmt.Errorf("starting the DNS service: %w", err)
	}
	ok := false
	for i := 0; i < 40 && !ok; i++ {
		time.Sleep(250 * time.Millisecond)
		ok = dnsAnswers()
	}
	before, _ := readDNSBefore()
	adapters, err := managedAdapters()
	if err != nil {
		return err
	}
	if !ok {
		// An update that won't start must not leave Windows with no DNS.
		restoreAdapters(adapters, before)
		return fmt.Errorf("the DNS service didn't start, so DNS settings were left automatic or as before; see %s", dnsLogFile())
	}
	families := []bool{false}
	if dnsAnswersAt(dnsAddr6) {
		families = append(families, true)
	}
	if len(adapters) == 0 {
		fmt.Println("  no Wi-Fi or Ethernet adapter found: DNS not changed")
	}
	for _, a := range adapters {
		// Reported from what netsh said, not by reading the setting back:
		// Windows may not have saved it yet, which made this print nothing.
		failed := false
		for _, v6 := range families {
			if usesShooDNS(a, v6) {
				continue
			}
			// Saved before the change, so a crash in between can't lose
			// DNS servers set by hand.
			key := beforeKey(a.GUID, v6)
			before[key] = winnet.StaticDNS(a.GUID, v6)
			if err := writeDNSBefore(before); err != nil {
				return fmt.Errorf("saving the DNS settings: %w", err)
			}
			if err := setAdapterDNS(a, v6, shooDNS(v6)); err != nil {
				fmt.Printf("  %-24s DNS not changed: %v\n", a.Name, err)
				delete(before, key)
				failed = true
			}
		}
		if !failed {
			fmt.Printf("  %-24s DNS shoo\n", a.Name)
		}
	}
	flushDNSCache()
	return writeDNSBefore(before)
}

// restoreAdapters puts back the DNS settings of adapters using shoo's DNS.
func restoreAdapters(adapters []winnet.Adapter, before map[string][]string) {
	for _, a := range adapters {
		restored := false
		for _, v6 := range []bool{false, true} {
			if !usesShooDNS(a, v6) {
				continue
			}
			if err := setAdapterDNS(a, v6, before[beforeKey(a.GUID, v6)]); err != nil {
				fmt.Printf("  %-24s DNS: %v\n", a.Name, err)
				continue
			}
			restored = true
		}
		if restored {
			fmt.Printf("  %-24s DNS back to normal\n", a.Name)
		}
	}
	restoreAbsent(before)
	flushDNSCache()
}

// restoreAbsent puts back the DNS settings of adapters that are switched off
// or unplugged. Windows doesn't list those, but keeps their settings and uses
// them again later: left pointed at shoo, such an adapter would have no DNS
// once shoo is gone.
func restoreAbsent(before map[string][]string) {
	present, err := winnet.Adapters()
	if err != nil {
		return
	}
	for _, v6 := range []bool{false, true} {
		guids, err := winnet.Interfaces(v6)
		if err != nil {
			continue
		}
		static := func(guid string) []string { return winnet.StaticDNS(guid, v6) }
		for _, guid := range absentShooInterfaces(present, guids, v6, static) {
			name := winnet.ConnectionName(guid)
			if name == "" {
				name = guid
			}
			if err := winnet.SetStaticDNS(guid, v6, savedDNS(before, guid, v6)); err != nil {
				fmt.Printf("  %-24s DNS: %v\n", name, err)
				continue
			}
			fmt.Printf("  %-24s DNS back to normal (adapter off or unplugged)\n", name)
		}
	}
}

// absentShooInterfaces picks the interfaces in guids that Windows didn't list
// as present and whose DNS still points at shoo.
func absentShooInterfaces(present []winnet.Adapter, guids []string, v6 bool, static func(guid string) []string) []string {
	var out []string
	for _, g := range guids {
		listed := slices.ContainsFunc(present, func(a winnet.Adapter) bool { return strings.EqualFold(a.GUID, g) })
		if !listed && slices.Equal(static(g), shooDNS(v6)) {
			out = append(out, g)
		}
	}
	return out
}

// savedDNS is an adapter's DNS servers from before shoo. The registry and
// the adapter list may spell its GUID in different cases.
func savedDNS(before map[string][]string, guid string, v6 bool) []string {
	want := beforeKey(guid, v6)
	for k, v := range before {
		if strings.EqualFold(k, want) {
			return v
		}
	}
	return nil
}

// disableDNS (admin) stops the DNS service blocking for the user whose shoo
// folder is dir. If others on the PC still use it, it keeps running for
// them. Otherwise it puts the DNS settings back and removes the service, in
// that order, so that Windows always has a working DNS server.
func disableDNS(dir string) error {
	if !isAdmin() {
		return errors.New("needs admin rights: run `shoo disable`")
	}
	account, accountErr := winacl.LocalService()
	users, _ := readDNSUsers()
	if others := withoutDir(users, dir); len(others) > 0 {
		if err := writeDNSUsers(others); err != nil {
			return err
		}
		if accountErr == nil && filepath.IsAbs(dir) {
			winacl.Revoke(dir, account)
		}
		fmt.Println("  DNS service kept: other people on this PC use shoo")
		return restartDNSService()
	}
	before, _ := readDNSBefore()
	adapters, err := managedAdapters()
	if err != nil {
		return err
	}
	restoreAdapters(adapters, before)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(dnsService); err == nil {
		stopDNSService(s)
		err := s.Delete()
		s.Close()
		if err != nil {
			return fmt.Errorf("removing the DNS service: %w", err)
		}
	}
	if accountErr == nil && filepath.IsAbs(dir) {
		winacl.Revoke(dir, account) // only if it's still there
	}
	var failed []string
	beforeFile := filepath.Join(systemDir(), dnsBeforeFile)
	usersFile := filepath.Join(systemDir(), dnsUsersFile)
	for _, p := range []string{dnsBinary(), dnsLogFile(), beforeFile, beforeFile + ".tmp", usersFile, usersFile + ".tmp"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, p)
		}
	}
	os.Remove(systemDir()) // only if empty
	if len(failed) > 0 {
		return fmt.Errorf("could not remove %s", strings.Join(failed, ", "))
	}
	return nil
}
