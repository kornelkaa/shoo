//go:build darwin

package main

import (
	"os"
	"path/filepath"
)

// logsDir is where the recordings go: ~/Library/Logs.
func logsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs")
}
