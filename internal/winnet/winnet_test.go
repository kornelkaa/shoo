//go:build windows

package winnet

import (
	"slices"
	"strings"
	"testing"
)

func TestManaged(t *testing.T) {
	cases := []struct {
		a    Adapter
		want bool
	}{
		{Adapter{Type: typeWiFi, Description: "Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC"}, true},
		{Adapter{Type: typeEthernet, Description: "Intel(R) Ethernet Connection I219-V"}, true},
		{Adapter{Type: typeEthernet, Description: "Hyper-V Virtual Ethernet Adapter"}, false},
		{Adapter{Type: typeEthernet, Description: "VirtualBox Host-Only Ethernet Adapter"}, false},
		{Adapter{Type: typeEthernet, Description: "VMware Virtual Ethernet Adapter for VMnet8"}, false},
		{Adapter{Type: typeEthernet, Description: "TAP-Windows Adapter V9"}, false},
		{Adapter{Type: typeWiFi, Description: "Microsoft Wi-Fi Direct Virtual Adapter"}, false},
		{Adapter{Type: 53, Description: "Tailscale Tunnel"}, false},
		{Adapter{Type: 24, Description: "Software Loopback Interface 1"}, false},
	}
	for _, c := range cases {
		if got := c.a.Managed(); got != c.want {
			t.Errorf("Managed(%q) = %v", c.a.Description, got)
		}
	}
}

func TestParseServers(t *testing.T) {
	for in, want := range map[string][]string{
		"1.1.1.1,212.200.190.166": {"1.1.1.1", "212.200.190.166"},
		"192.168.1.1 8.8.8.8":     {"192.168.1.1", "8.8.8.8"},
		"2001:4860:4860::8888":    {"2001:4860:4860::8888"},
		"":                        nil,
		"nonsense":                nil,
	} {
		if got := parseServers(in); !slices.Equal(got, want) {
			t.Errorf("parseServers(%q) = %v", in, got)
		}
	}
}

func TestParseV6Binary(t *testing.T) {
	b := make([]byte, 33) // two addresses and a stray byte to ignore
	b[0], b[1], b[15] = 0x20, 0x01, 0x01
	b[16], b[31] = 0xfe, 0x02
	if got := parseV6Binary(b); !slices.Equal(got, []string{"2001::1", "fe00::2"}) {
		t.Errorf("got %v", got)
	}
}

func TestAdaptersOnThisComputer(t *testing.T) {
	as, err := Adapters()
	if err != nil {
		t.Fatal(err)
	}
	if len(as) == 0 {
		t.Fatal("no adapters")
	}
	for _, a := range as {
		if a.GUID == "" || a.Index == 0 {
			t.Errorf("incomplete adapter: %+v", a)
		}
	}

	// Every real adapter Windows lists has settings Interfaces finds, and a
	// name ConnectionName finds.
	guids, err := Interfaces(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if !a.Managed() {
			continue
		}
		if !slices.ContainsFunc(guids, func(g string) bool { return strings.EqualFold(g, a.GUID) }) {
			t.Errorf("Interfaces is missing %s (%s)", a.GUID, a.Name)
		}
		if got := ConnectionName(a.GUID); got != a.Name {
			t.Errorf("ConnectionName(%s) = %q, want %q", a.GUID, got, a.Name)
		}
	}
}
