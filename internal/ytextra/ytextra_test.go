package ytextra

import (
	"strings"
	"testing"

	"ytblock/internal/prune"
)

// Shape of a real get_watch response: a list of parts, the first holding
// the player data with its ad fields.
const getWatch = `[{"responseContext":{},"playerResponse":{"videoDetails":{"videoId":"abc"},"adPlacements":[{"adPlacementRenderer":{}}],"playerAds":[{}],"adBreakHeartbeatParams":"Q0FB"},"responseType":"PLAYER"},` +
	`{"responseContext":{},"watchNextResponse":{"contents":{"x":1}},"responseType":"WATCH_NEXT"}]`

func TestGetWatchAdsRemoved(t *testing.T) {
	r := Rules()
	if !r.Matches("/youtubei/v1/get_watch") {
		t.Fatal("get_watch should be edited")
	}
	out, n, err := r.JSON([]byte(getWatch))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if n != 3 || strings.Contains(s, "adPlacements") || strings.Contains(s, "playerAds") || strings.Contains(s, "adBreakHeartbeatParams") {
		t.Fatalf("removed %d: %s", n, s)
	}
	if !strings.Contains(s, `"videoId":"abc"`) || !strings.Contains(s, `"watchNextResponse"`) {
		t.Fatalf("video data lost: %s", s)
	}
}

func TestOriginalRulesKept(t *testing.T) {
	r := Rules()
	for _, p := range prune.Default.Paths {
		if !r.Matches(p) {
			t.Errorf("lost original path %s", p)
		}
	}
	if strings.Join(r.Keys, ",") != strings.Join(prune.Default.Keys, ",") {
		t.Error("keys changed")
	}
	if prune.Default.Matches("/youtubei/v1/get_watch") {
		t.Error("prune.Default must not be modified")
	}
}
