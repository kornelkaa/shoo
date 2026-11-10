//go:build linux

package main

import (
	"os"
	"path/filepath"
)

// logsDir is where the recordings go: ~/.local/state (or $XDG_STATE_HOME).
func logsDir() string {
	if s := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(s) {
		return s
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state")
}
