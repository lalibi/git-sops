package agekey

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGeneratedKeyHasOwnerOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	t.Setenv("SOPS_AGE_KEY_FILE", path)
	if _, err := Generate(); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if sd.String() != want.String() {
		t.Fatalf("unexpected identity ACL: %s", sd.String())
	}
}
