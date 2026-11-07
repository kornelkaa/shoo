//go:build windows

package dnsblock

import "shoo/internal/winnet"

// systemServers asks Windows for the DNS servers the networks handed out,
// which it remembers even while an adapter is pointed at shoo. Servers set by
// hand before shoo are in Upstreams.Preferred.
func systemServers() []string {
	adapters, err := winnet.Adapters()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range adapters {
		if a.Up && a.Managed() {
			out = append(out, winnet.DHCPDNS(a.GUID, false)...)
			out = append(out, winnet.DHCPDNS(a.GUID, true)...)
		}
	}
	return out
}
