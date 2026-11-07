//go:build windows

package certs

import "shoo/internal/winacl"

func ownerOnly(path string) error { return winacl.OwnerOnly(path) }
