package dnsblock

import (
	"slices"
	"testing"
)

func TestParseNMCLI(t *testing.T) {
	// `nmcli -t -g IP4.DNS,IP6.DNS,DHCP4.OPTION,DHCP6.OPTION device show`
	// for a Wi-Fi device, then loopback (no values).
	out := `127.0.0.1
fe80\:\:1
broadcast_address = 192.168.1.255 | dhcp_server_identifier = 192.168.1.1 | domain_name_servers = 192.168.1.1 9.9.9.9 | ip_address = 192.168.1.23
dhcp6_name_servers = 2001\:db8\:\:53 | dhcp6_domain_search = lan



`
	got := parseNMCLI(out)
	want := []string{"127.0.0.1", "fe80::1", "192.168.1.1", "9.9.9.9", "2001:db8::53"}
	if !slices.Equal(got, want) {
		t.Errorf("parseNMCLI = %q, want %q", got, want)
	}
}

func TestParseResolvConf(t *testing.T) {
	in := `# This is /run/systemd/resolve/resolv.conf
nameserver 192.168.1.1
nameserver   2001:db8::1
nameserver not-an-ip
search lan
`
	got := parseResolvConf(in)
	if want := []string{"192.168.1.1", "2001:db8::1"}; !slices.Equal(got, want) {
		t.Errorf("parseResolvConf = %q, want %q", got, want)
	}
}
