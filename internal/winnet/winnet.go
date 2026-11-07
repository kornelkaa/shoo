//go:build windows

// Package winnet lists Windows network adapters and reads their DNS settings.
// It reads the registry rather than running netsh, whose text depends on the
// system's language.
package winnet

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	typeEthernet = 6
	typeWiFi     = 71
	operUp       = 1
)

// Adapter is one network adapter.
type Adapter struct {
	GUID        string // {xxxxxxxx-...}, its name in the registry
	Name        string // what Windows shows, e.g. "Wi-Fi"
	Description string // the hardware, e.g. "Realtek ... Wireless"
	Index       uint32
	Type        uint32
	Up          bool
}

// Adapters lists the network adapters, connected or not.
func Adapters() ([]Adapter, error) {
	size := uint32(32 * 1024)
	for try := 0; ; try++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW && try < 4 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing network adapters: %w", err)
		}
		var out []Adapter
		for a := first; a != nil; a = a.Next {
			index := a.IfIndex
			if index == 0 {
				index = a.Ipv6IfIndex
			}
			out = append(out, Adapter{
				GUID:        windows.BytePtrToString(a.AdapterName),
				Name:        windows.UTF16PtrToString(a.FriendlyName),
				Description: windows.UTF16PtrToString(a.Description),
				Index:       index,
				Type:        a.IfType,
				Up:          a.OperStatus == operUp,
			})
		}
		return out, nil
	}
}

// Managed reports whether shoo sets this adapter's DNS: real Ethernet and
// Wi-Fi only. Virtual machine networks don't reach the internet by themselves,
// and VPNs bring DNS servers that their private names depend on.
func (a Adapter) Managed() bool {
	if a.Type != typeEthernet && a.Type != typeWiFi {
		return false
	}
	d := strings.ToLower(a.Description)
	for _, s := range []string{"virtual", "vmware", "tap-", "wintun", "wireguard", "tailscale", "vpn", "bluetooth"} {
		if strings.Contains(d, s) {
			return false
		}
	}
	return true
}

// StaticDNS returns the DNS servers set by hand on an adapter. Empty means
// automatic. v6 selects the adapter's IPv6 settings, which are separate.
func StaticDNS(guid string, v6 bool) []string {
	k, err := interfaceKey(guid, v6)
	if err != nil {
		return nil
	}
	defer k.Close()
	s, _, err := k.GetStringValue("NameServer")
	if err != nil {
		return nil
	}
	return parseServers(s)
}

// DHCPDNS returns the DNS servers the network handed out to an adapter. It
// stays correct while StaticDNS points somewhere else.
func DHCPDNS(guid string, v6 bool) []string {
	k, err := interfaceKey(guid, v6)
	if err != nil {
		return nil
	}
	defer k.Close()
	if v6 {
		b, _, err := k.GetBinaryValue("Dhcpv6DNSServers")
		if err != nil {
			return nil
		}
		return parseV6Binary(b)
	}
	s, _, err := k.GetStringValue("DhcpNameServer")
	if err != nil {
		return nil
	}
	return parseServers(s)
}

// Interfaces lists the GUIDs of every network interface Windows keeps
// settings for, including disabled and unplugged adapters, which Adapters
// doesn't list.
func Interfaces(v6 bool) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, interfacesPath(v6), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

// SetStaticDNS writes an interface's DNS servers straight into its settings
// (empty: automatic). Windows uses them when the adapter is next enabled or
// plugged in. It's for adapters netsh can't reach because they're switched
// off; it needs admin rights.
func SetStaticDNS(guid string, v6 bool, servers []string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, interfacesPath(v6)+`\`+guid, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("NameServer", strings.Join(servers, ","))
}

// ConnectionName is the name Windows shows for an adapter ("Wi-Fi"), also
// while it's switched off ("" if unknown).
func ConnectionName(guid string) string {
	const network = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, network+guid+`\Connection`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("Name")
	return name
}

func interfacesPath(v6 bool) string {
	stack := "Tcpip"
	if v6 {
		stack = "Tcpip6"
	}
	return `SYSTEM\CurrentControlSet\Services\` + stack + `\Parameters\Interfaces`
}

func interfaceKey(guid string, v6 bool) (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, interfacesPath(v6)+`\`+guid, registry.QUERY_VALUE)
}

// parseServers reads "1.1.1.1,8.8.8.8" or "1.1.1.1 8.8.8.8".
func parseServers(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if net.ParseIP(f) != nil {
			out = append(out, f)
		}
	}
	return out
}

// parseV6Binary reads a list of 16-byte IPv6 addresses.
func parseV6Binary(b []byte) []string {
	var out []string
	for ; len(b) >= net.IPv6len; b = b[net.IPv6len:] {
		out = append(out, net.IP(b[:net.IPv6len]).String())
	}
	return out
}
