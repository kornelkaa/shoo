package main

// Windows system integration: the certificate store, the proxy setting and
// admin rights. Unlike on macOS the proxy setting belongs to the user, so
// only DNS needs admin rights.

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"shoo/internal/certs"
	"shoo/internal/winacl"
	"shoo/internal/winnet"
)

// What the shared code says on this system.
const (
	osName       = "Windows"
	computerName = "PC"
	reopenHint   = "Close your browser completely and open it again."
	reopenBrief  = "reopen your browser if it doesn't"
	notAdminHint = "from a normal terminal, not as administrator; Windows asks when it needs to"
	trustPrompt  = "Windows will ask you to confirm"
	stopNote     = "shoo is stopped until `shoo start`.\nMeanwhile YouTube shows ads. Ad domains on other sites stay blocked (DNS keeps running)."
	certStore    = "certificate store"
)

// usageSteps is the part of the help that names system-specific commands.
const usageSteps = `  shoo enable [-force] [-dns -data DIR]
                            turn shoo on in the Windows proxy settings
                               (-dns: also install the ad-blocking DNS service
                               for the shoo folder DIR and use it as DNS)
  shoo disable              turn shoo off in the Windows proxy settings (also DNS)
  shoo disable-dns          only remove the DNS service and restore DNS
`

// system returns the full path of a Windows tool, so that a program with
// admin rights never picks up a file of that name from somewhere else.
func system(name string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return name
	}
	return filepath.Join(dir, name)
}

// quiet runs a system tool, showing its output only if it fails. The tools'
// messages depend on the system's language, so only the exit code is used.
func quiet(tool string, args ...string) error {
	out, err := exec.Command(system(tool), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", tool, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isAdmin reports whether shoo is running with admin rights.
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// dataBase is the folder shoo's own folder goes in: %LOCALAPPDATA%. Not
// %APPDATA%, which can follow the user to other computers, private key and all.
func dataBase() (string, error) { return os.UserCacheDir() }

// elevate runs this program again with admin rights, which shows Windows'
// confirmation window, and waits for it. Its output appears in this terminal.
func elevate(exe string, args ...string) error {
	if isAdmin() {
		cmd := exec.Command(exe, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}
	args = append(args, "-console", fmt.Sprint(os.Getpid()))
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return err
	}
	info := shellExecuteInfo{mask: seeMaskNoCloseProcess, verb: verb, file: file, params: params, show: windows.SW_HIDE}
	info.size = uint32(unsafe.Sizeof(info))
	r, _, callErr := shellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return errors.New("cancelled in the Windows confirmation window")
		}
		return callErr
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the admin step failed (exit code %d)", code)
	}
	return nil
}

const seeMaskNoCloseProcess = 0x40

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	size     uint32
	mask     uint32
	hwnd     windows.Handle
	verb     *uint16
	file     *uint16
	params   *uint16
	dir      *uint16
	show     int32
	instApp  windows.Handle
	idList   uintptr
	class    *uint16
	keyClass windows.Handle
	hotKey   uint32
	icon     windows.Handle
	process  windows.Handle
}

var (
	shell32        = windows.NewLazySystemDLL("shell32.dll")
	shellExecuteEx = shell32.NewProc("ShellExecuteExW")
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procFreeCons   = kernel32.NewProc("FreeConsole")
	procAttachCons = kernel32.NewProc("AttachConsole")
	wininet        = windows.NewLazySystemDLL("wininet.dll")
	internetSetOpt = wininet.NewProc("InternetSetOptionW")
)

// attachConsole sends this admin process's output to the terminal of the
// process that started it (see elevate). pid is 0 otherwise.
func attachConsole(pid int) {
	if pid == 0 {
		return
	}
	procFreeCons.Call()
	if r, _, _ := procAttachCons.Call(uintptr(pid)); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout, os.Stderr = f, f
		log.SetOutput(f)
	}
}

// trust adds the CA to the user's trusted root certificates. Windows shows
// a confirmation window. Edge, Chrome and Internet Settings read this store.
func trust(dir string) error {
	return quiet("certutil.exe", "-user", "-f", "-addstore", "Root", filepath.Join(dir, certs.CertFile))
}

// untrust removes the certificate from the store.
func untrust(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, certs.CertFile))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("certificate file is not valid PEM")
	}
	// Ignore "not found" errors: the goal is just that it's gone.
	quiet("certutil.exe", "-user", "-delstore", "Root", fmt.Sprintf("%x", sha1.Sum(block.Bytes)))
	return nil
}

// isTrusted asks Windows (Go's Verify uses the system's check here) whether
// a YouTube certificate signed by our CA would be accepted.
func isTrusted(dir string) (bool, error) {
	ca, err := certs.Load(dir)
	if err != nil {
		return false, err
	}
	leaf, err := ca.LeafFor("www.youtube.com")
	if err != nil {
		return false, err
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return false, err
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: "www.youtube.com"})
	return err == nil, nil
}

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// proxySetting reads the user's proxy configuration script and whether a
// fixed proxy server is switched on.
func proxySetting() (pac string, manual bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	pac, _, _ = k.GetStringValue("AutoConfigURL")
	on, _, _ := k.GetIntegerValue("ProxyEnable")
	return pac, on != 0
}

// proxyChanged tells running programs to read the proxy setting again.
func proxyChanged() {
	const settingsChanged, refresh = 39, 37
	internetSetOpt.Call(0, settingsChanged, 0, 0)
	internetSetOpt.Call(0, refresh, 0, 0)
}

func enabledEverywhere(pacURL string) bool {
	pac, _ := proxySetting()
	return pac == pacURL
}

// enable points the user's proxy setting at our PAC file. It won't replace a
// different proxy setting the user already has, unless force is set.
func enable(pacURL string, force bool) error {
	cur, manual := proxySetting()
	if !force {
		if cur != "" && !isShooPAC(cur) {
			fmt.Printf("  %-24s skipped: already uses %s (use -force to replace)\n", "System proxy", cur)
			return nil
		}
		if manual {
			fmt.Printf("  %-24s skipped: a proxy server is set (use -force to replace)\n", "System proxy")
			return nil
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("AutoConfigURL", pacURL); err != nil {
		return err
	}
	proxyChanged()
	fmt.Printf("  %-24s on\n", "System proxy")
	return nil
}

// disable turns the proxy setting off, only if it's ours.
func disable(pacURL string) error {
	cur, _ := proxySetting()
	if !isShooPAC(cur) {
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue("AutoConfigURL"); err != nil {
		return err
	}
	proxyChanged()
	fmt.Printf("  %-24s off\n", "System proxy")
	return nil
}

// cmdEnable is `shoo enable`.
func cmdEnable(dir, pacURL string, force, dnsOn bool) error {
	if err := enable(pacURL, force); err != nil || !dnsOn {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return elevate(exe, "enable-dns", "-data", dir)
}

// cmdDisable is `shoo disable`.
func cmdDisable(dir, pacURL string) error {
	err := disable(pacURL)
	if !dnsServes(dir) {
		return err
	}
	exe, exeErr := os.Executable()
	if exeErr != nil {
		return exeErr
	}
	if dnsErr := elevate(exe, "disable-dns", "-data", dir); err == nil {
		err = dnsErr
	}
	return err
}

// applyNetwork makes the changes setup found were needed.
func applyNetwork(exe, dir, addr, pacURL string, wantDNS, dnsOn, dnsOff bool) error {
	if err := enable(pacURL, false); err != nil {
		return fmt.Errorf("turning on the proxy setting: %w", err)
	}
	if !dnsOn && !dnsOff {
		return nil
	}
	fmt.Println("  changing DNS needs admin rights: Windows will ask you to confirm")
	if !protectedBinary(exe) {
		fmt.Printf("  note: %s can be changed without admin rights; installing with\n"+
			"  install.ps1 protects it, so nothing can swap it before it runs as admin\n", exe)
	}
	if dnsOn {
		if err := elevate(exe, "enable-dns", "-data", dir); err != nil {
			return fmt.Errorf("turning on DNS: %w", err)
		}
	}
	if dnsOff {
		if err := elevate(exe, "disable-dns", "-data", dir); err != nil {
			return fmt.Errorf("removing the DNS service: %w", err)
		}
	}
	return nil
}

// turnOffNetwork is uninstall's network step. One admin step removes the DNS
// service (if this user uses it) and shoo itself (see removeProgram).
func turnOffNetwork(exe, dir, addr, pacURL string) error {
	err := disable(pacURL)
	if dnsServes(dir) || programInstalled() {
		if aerr := elevate(exe, "remove-program", "-dns", "-data", dir); err == nil {
			err = aerr
		}
	}
	if err != nil {
		return fmt.Errorf("%w; run `shoo uninstall` again", err)
	}
	return nil
}

// protectedBinary reports whether only an admin can change exe.
func protectedBinary(exe string) bool {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(pf, exe)
	return err == nil && !strings.HasPrefix(rel, "..")
}

// networkStatus is the last part of `shoo status`.
func networkStatus(pacURL string, showDNS bool) {
	fmt.Println("Network:")
	cur, _ := proxySetting()
	fmt.Printf("  %-24s %s\n", "System proxy", pacLine(cur, cur != "", pacURL))
	if !showDNS {
		return
	}
	adapters, _ := managedAdapters()
	for _, a := range adapters {
		line := "DNS not shoo"
		if usesShooDNS(a, false) {
			line = "DNS shoo"
		}
		if !a.Up {
			line += " (not connected)"
		}
		fmt.Printf("  %-24s %s\n", a.Name, line)
	}
}

func managedAdapters() ([]winnet.Adapter, error) {
	all, err := winnet.Adapters()
	if err != nil {
		return nil, err
	}
	var out []winnet.Adapter
	for _, a := range all {
		if a.Managed() {
			out = append(out, a)
		}
	}
	return out, nil
}

// permissionsText is what setup says it will ask for.
func permissionsText(trusted bool) string {
	certLine := "• Windows asks once, in a security warning, to trust shoo's certificate.\n" +
		"  With it shoo decrypts websites on this PC to remove ads and hide ad\n" +
		"  boxes. Banks, logins, payments and Windows services are never\n" +
		"  decrypted, and the certificate can't be used for them. The key\n" +
		"  never leaves your PC."
	if trusted {
		certLine = "• The certificate is already trusted: no need to confirm it\n" +
			"  (unless it's old or expires soon: then it's replaced, which asks once)."
	}
	return certLine + "\n" +
		"• Websites go through shoo's proxy. This is your own setting: no admin\n" +
		"  rights needed.\n" +
		"• If blocking other websites, Windows asks once for admin rights to\n" +
		"  install shoo's DNS service, which answers ad domains with a dead address.\n" +
		"• Running in the background needs no admin rights."
}

// Per-user proxy ports: portBase plus a number from the user's account.
const (
	portBase  = 18000
	portRange = 1000
)

// chooseAddr picks this user's proxy address, which setup saves. The proxy
// setting is each user's own, so people sharing the PC each get their own
// proxy, with their own certificate and lists. The port comes from the
// account, so it stays the same; a port that's taken (another user's proxy)
// or reserved by Windows is skipped.
func chooseAddr() (string, error) {
	sid, err := winacl.CurrentUser()
	if err != nil {
		return "", err
	}
	start := userPort(sid)
	for i := 0; i < portRange; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", portBase+(start+i)%portRange)
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			return addr, nil
		}
	}
	return "", errors.New("no free port for shoo's proxy")
}

// userPort is a number below portRange from an account's SID. Its last part
// (the RID) numbers the accounts on a PC (1001, 1002...), so they differ.
func userPort(sid string) int {
	rid, err := strconv.Atoi(sid[strings.LastIndexByte(sid, '-')+1:])
	if err != nil || rid < 0 {
		return 0
	}
	return rid % portRange
}
