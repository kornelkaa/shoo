//go:build windows

package certs

import (
	"slices"
	"testing"

	"shoo/internal/winacl"
)

func checkKeyPrivate(t *testing.T, path string) {
	t.Helper()
	me, err := winacl.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	sids, err := winacl.Entries(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sids, []string{me}) {
		t.Errorf("key is readable by %v, want only %s", sids, me)
	}
}
