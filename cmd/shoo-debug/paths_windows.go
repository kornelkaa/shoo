//go:build windows

package main

import "os"

// dataBase is the folder shoo's own folder is in.
func dataBase() (string, error) { return os.UserCacheDir() }

// logsDir is where the recordings go: shoo's own folder.
func logsDir(dataDir string) string { return dataDir }
