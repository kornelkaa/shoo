package ytskip

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const page = `<!DOCTYPE html><html><head><script nonce="abc-123_X">var ytInitialPlayerResponse = {"adPlacements":[1]};</script></head><body></body></html>`

func TestInject(t *testing.T) {
	out := string(Inject([]byte(page)))
	if !strings.HasPrefix(out, `<!DOCTYPE html><html><head><script nonce="abc-123_X">(function () {`) {
		t.Fatalf("script not at start of head: %s", out[:120])
	}
	if !strings.HasSuffix(out, page[len(`<!DOCTYPE html><html><head>`):]) {
		t.Error("rest of page changed")
	}
	if strings.Contains(Script, "innerHTML") || strings.Contains(Script, "ytInitial") {
		t.Error("script must not set HTML or use names the YouTube code edits")
	}
	for _, p := range []string{"<html><body>no head</body></html>", "<head><script>no nonce</script></head>"} {
		if string(Inject([]byte(p))) != p {
			t.Errorf("%q should be unchanged", p)
		}
	}
}

func TestTransportOnlyEditsPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/watch" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		io.WriteString(w, page)
	}))
	defer srv.Close()
	// Every host goes to the test server.
	next := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	tr := &Transport{Next: next, Log: log.New(io.Discard, "", 0)}
	for path, edited := range map[string]bool{
		"http://www.youtube.com/watch":              true,
		"http://www.youtube.com/youtubei/v1/player": false,
		"http://www.dictionary.com/watch":           false, // not YouTube
	} {
		req, _ := http.NewRequest("GET", path, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := strings.Contains(string(b), "__shooSkip"); got != edited {
			t.Errorf("%s: edited=%v, want %v", path, got, edited)
		}
		if edited && resp.ContentLength != int64(len(b)) {
			t.Errorf("%s: Content-Length %d, body %d", path, resp.ContentLength, len(b))
		}
	}
}
