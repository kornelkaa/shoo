//go:build !windows

package certs

// ownerOnly has nothing to do here: the file's mode is enough.
func ownerOnly(string) error { return nil }
