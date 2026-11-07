//go:build windows

package winacl

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOwnerOnly(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OwnerOnly(f); err != nil {
		t.Fatal(err)
	}
	me, err := CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	sids, err := Entries(f)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sids, []string{me}) {
		t.Errorf("entries = %v, want only %s", sids, me)
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "secret" {
		t.Errorf("owner can't read it: %q, %v", b, err)
	}
}

func TestGrantSkipsOwnerOnlyFiles(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	list := filepath.Join(dir, "list")
	for _, f := range []string{key, list} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := OwnerOnly(key); err != nil {
		t.Fatal(err)
	}
	ls, err := LocalService()
	if err != nil {
		t.Fatal(err)
	}
	if err := Grant(dir, ls, Read); err != nil {
		t.Fatal(err)
	}
	has := func(p string) bool {
		sids, err := Entries(p)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(sids, ls.String())
	}
	if !has(list) {
		t.Error("an existing file didn't inherit the grant")
	}
	if has(key) {
		t.Error("the key must not inherit the grant")
	}
	// List updates write a temporary file and rename it.
	later := filepath.Join(dir, "later")
	if err := os.WriteFile(later+".tmp", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(later+".tmp", later); err != nil {
		t.Fatal(err)
	}
	if !has(later) {
		t.Error("an updated list didn't inherit the grant")
	}
	if err := Revoke(dir, ls); err != nil {
		t.Fatal(err)
	}
	if has(list) || has(dir) {
		t.Error("Revoke left the grant in place")
	}
}
