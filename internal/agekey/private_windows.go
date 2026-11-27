package agekey

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows ignores Unix permission bits on creation. Supply a protected DACL
// at CreateFile time and replace any existing DACL before appending a key.
func openPrivate(path string, exclusive bool) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	disposition := uint32(windows.OPEN_ALWAYS)
	if exclusive {
		disposition = windows.CREATE_NEW
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	h, err := windows.CreateFile(name, windows.FILE_APPEND_DATA|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ, &sa, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open private key file", Path: path, Err: err}
	}
	if !exclusive {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			windows.CloseHandle(h)
			return nil, &os.PathError{Op: "set key file permissions", Path: path, Err: err}
		}
	}
	return os.NewFile(uintptr(h), path), nil
}
