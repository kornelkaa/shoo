//go:build windows

package sites

import _ "embed"

// platformExclusions are this system's additions to exclusions.txt. They're
// separate because the never-decrypt list is written into the certificate:
// adding to the shared list would make people on the other system replace
// theirs.
//
//go:embed exclusions_windows.txt
var platformExclusions string
