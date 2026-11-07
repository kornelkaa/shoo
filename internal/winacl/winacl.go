//go:build windows

// Package winacl sets file permissions on Windows, where Go's file modes
// (0o600 and so on) only control the read-only flag.
package winacl

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Read lets an account read files and list folders.
	Read = windows.GENERIC_READ | windows.GENERIC_EXECUTE
	// Write lets an account read and write a file.
	Write = windows.GENERIC_READ | windows.GENERIC_WRITE
)

// OwnerOnly makes path accessible to the current user and nobody else, and
// stops it inheriting any other permissions from its folder.
func OwnerOnly(path string) error {
	sid, err := currentUser()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry(sid, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("restricting %s: %w", path, err)
	}
	return nil
}

// Grant adds access for the account sid to path. A folder's files and
// subfolders get it too, unless they block inheritance (see OwnerOnly).
func Grant(path string, sid *windows.SID, access windows.ACCESS_MASK) error {
	return change(path, entry(sid, access, windows.GRANT_ACCESS, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT))
}

// Revoke removes everything Grant gave the account sid.
func Revoke(path string, sid *windows.SID) error {
	return change(path, entry(sid, 0, windows.REVOKE_ACCESS, windows.NO_INHERITANCE))
}

// LocalService is the low-privilege account shoo's DNS service runs as.
func LocalService() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinLocalServiceSid)
}

// CurrentUser is the SID, as text, of the account shoo is running as.
func CurrentUser() (string, error) {
	sid, err := currentUser()
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

// Entries returns the accounts in path's permissions, as SIDs.
func Entries(path string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	var sids []string
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return nil, err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = append(sids, sid.String())
	}
	return sids, nil
}

func currentUser() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

func entry(sid *windows.SID, access windows.ACCESS_MASK, mode windows.ACCESS_MODE, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        mode,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func change(path string, e windows.EXPLICIT_ACCESS) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	cur, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{e}, cur)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("changing permissions of %s: %w", path, err)
	}
	return nil
}
