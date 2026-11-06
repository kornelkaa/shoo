package filterlist

import (
	"slices"
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	in := `[Adblock Plus 2.0]
! comment
||a.example^

!#if env_firefox
||firefox-only.example^
!#if cap_html_filtering
||nested.example^
!#endif
!#else
||else-branch.example^
!#endif
!#include filters-extra.txt
  ||b.example^
`
	var got []string
	if err := Scan(strings.NewReader(in), func(l string) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	if want := []string{"||a.example^", "||b.example^"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
