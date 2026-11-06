// Package ytextra adds YouTube rules on top of the original, unchanged
// YouTube code (internal/prune). The YouTube proxy reads its rules as data,
// so extra places to remove ads from are added here instead of editing it.
package ytextra

import "ytblock/internal/prune"

// ExtraPaths are YouTube data requests that also carry ad instructions.
var ExtraPaths = []string{
	// get_watch returns a video's player data (with its ads) and the
	// next-video list in one response. YouTube uses it instead of
	// /player + /next for some video clicks, which let ads through.
	"/youtubei/v1/get_watch",
}

// Rules returns the original rules (prune.Default) plus ExtraPaths.
// prune.Default itself is not modified.
func Rules() prune.Rules {
	r := prune.Default
	r.Paths = append(append([]string{}, prune.Default.Paths...), ExtraPaths...)
	r.Keys = append([]string{}, prune.Default.Keys...)
	r.HTMLVars = append([]string{}, prune.Default.HTMLVars...)
	return r
}
