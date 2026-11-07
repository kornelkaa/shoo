//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

// dataBase is the folder shoo's own folder is in.
func dataBase() (string, error) { return os.UserConfigDir() }

// logsDir is where the recordings go: ~/Library/Logs.
func logsDir(string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs")
}
