package main

// The questions `shoo setup` asks, and where the answers are kept.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/charmbracelet/huh"

	"shoo/internal/sites"
)

const settingsFile = "settings.json"

// Settings are the choices made in `shoo setup`.
type Settings struct {
	// Sites is the ad-domain level for other websites: "off" or a key of
	// sites.Levels. YouTube ads are always blocked.
	Sites string `json:"sites"`
	// StartAtLogin runs shoo in the background after login. When false,
	// it runs until logout and is started again with `shoo start`.
	StartAtLogin bool `json:"start_at_login"`
}

const sitesOff = "off"

// loadSettings returns the saved settings, or defaults that match an
// existing install (its list level) when nothing is saved yet.
func loadSettings(dir string) Settings {
	s := Settings{Sites: sites.DefaultLevel, StartAtLogin: true}
	if b, err := os.ReadFile(filepath.Join(dir, settingsFile)); err == nil {
		var saved Settings
		if json.Unmarshal(b, &saved) == nil && saved.valid() == nil {
			return saved
		}
	}
	if l := currentLevel(dir); l != "" {
		s.Sites = l
	}
	return s
}

func (s Settings) valid() error {
	if _, ok := sites.Levels[s.Sites]; !ok && s.Sites != sitesOff {
		return fmt.Errorf("unknown level %q", s.Sites)
	}
	return nil
}

func saveSettings(dir string, s Settings) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(dir, settingsFile), append(b, '\n'), 0o644)
}

// currentLevel names the level the downloaded list came from ("" if there is
// no list or it was made from custom URLs).
func currentLevel(dir string) string {
	src := sites.Sources(dir)
	for name, urls := range sites.Levels {
		if slices.Equal(src, urls) {
			return name
		}
	}
	return ""
}

// askSettings shows the setup questions, starting from cur. ok is false if
// the user cancelled.
func askSettings(cur Settings, trusted bool) (s Settings, ok bool, err error) {
	s, ok = cur, true

	certLine := "• macOS asks for your password once, to trust shoo's certificate.\n" +
		"  It only works for youtube.com, so it can't be used to read other websites."
	if trusted {
		certLine = "• The certificate is already trusted: no password needed for it."
	}
	perms := certLine + "\n" +
		"• Terminal asks for your password (sudo) once, to point macOS's network\n" +
		"  settings at shoo. Only YouTube and ad domains go through it.\n" +
		"• Running in the background needs no password."

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Block ads on other websites?").
				Description("YouTube ads are always blocked.").
				Options(
					huh.NewOption("Off       (YouTube only)", sitesOff),
					huh.NewOption("Balanced  (~78k ad domains, fewest broken sites)", "balanced"),
					huh.NewOption("Strict    (~280k ad domains, recommended)", "strict"),
					huh.NewOption("Max       (~290k, also blocks more trackers)", "max"),
				).
				Value(&s.Sites),
			huh.NewConfirm().
				Title("Start shoo automatically when you log in?").
				Description("If not, start it with `shoo start` when you want it.").
				Affirmative("Yes").
				Negative("No").
				Value(&s.StartAtLogin),
		),
		huh.NewGroup(
			huh.NewNote().
				Title("Permissions").
				Description(perms),
			huh.NewConfirm().
				Title("Set up shoo now?").
				Affirmative("Yes, continue").
				Negative("Cancel").
				Value(&ok),
		),
	)
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return cur, false, nil
		}
		return cur, false, err
	}
	return s, ok, nil
}

// interactive reports whether stdin is a terminal a person can answer in.
func interactive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
