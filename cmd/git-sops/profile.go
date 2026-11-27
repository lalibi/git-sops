package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
)

const profileBegin = "# BEGIN git-sops PowerShell completion"
const profileEnd = "# END git-sops PowerShell completion"

func psLiteral(s string) string {
	// PowerShell treats smart single quotes as string delimiters too.
	escape := strings.NewReplacer("'", "''", "‘", "‘‘", "’", "’’", "‚", "‚‚", "‛", "‛‛")
	return "'" + escape.Replace(s) + "'"
}

func profileBlock(exe string) string {
	path := psLiteral(exe)
	// A BOM-less profile may use the Windows ANSI code page or UTF-8.
	// Keep the loader ASCII so either shell can read a Unicode executable path.
	if strings.IndexFunc(exe, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
		path = "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString([]byte(exe)) + "')))"
	}
	return profileBegin + "\n& " + path + " completion powershell | Out-String | Invoke-Expression\n" + profileEnd
}

// Decode only for inspecting lines. Existing bytes, the BOM, file permissions
// and symlink targets are preserved by appending through the original file.
func profileEncoding(data []byte) (body []byte, enc encoding.Encoding) {
	for _, format := range []struct {
		bom string
		enc encoding.Encoding
	}{
		{"\xff\xfe\x00\x00", utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM)},
		{"\x00\x00\xfe\xff", utf32.UTF32(utf32.BigEndian, utf32.IgnoreBOM)},
		{"\xff\xfe", unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)},
		{"\xfe\xff", unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)},
		{"\xef\xbb\xbf", encoding.Nop},
	} {
		if bytes.HasPrefix(data, []byte(format.bom)) {
			return data[len(format.bom):], format.enc
		}
	}
	return data, encoding.Nop
}

func installProfileBlock(path, block string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	// Serialize the marker check and append across simultaneous installers.
	lock, err := os.OpenFile(path+".git-sops.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false, fmt.Errorf("lock PowerShell profile: %w", err)
	}
	defer func() { lock.Close(); os.Remove(lock.Name()) }()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("expected a regular profile file at %q", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	body, enc := profileEncoding(data)
	decoded, err := enc.NewDecoder().Bytes(body)
	if err != nil {
		return false, err
	}
	text := string(decoded)
	seenBegin, seenEnd := false, false
	for line := range strings.SplitSeq(text, "\n") {
		switch strings.TrimSpace(line) {
		case profileBegin:
			if seenBegin {
				return false, fmt.Errorf("duplicate git-sops completion block in %q", path)
			}
			seenBegin = true
		case profileEnd:
			if !seenBegin || seenEnd {
				return false, fmt.Errorf("unmatched git-sops completion marker in %q", path)
			}
			seenEnd = true
		}
	}
	if seenBegin && !seenEnd {
		return false, fmt.Errorf("missing git-sops completion end marker in %q", path)
	}
	if seenEnd {
		return false, nil
	}
	newline := "\n"
	if strings.Contains(text, "\r\n") || (!strings.Contains(text, "\n") && runtime.GOOS == "windows") {
		newline = "\r\n"
	}
	addition := strings.ReplaceAll(block+"\n", "\n", newline)
	if text != "" && !strings.HasSuffix(text, "\n") {
		addition = newline + addition
	}
	encoded, err := enc.NewEncoder().String(addition)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(encoded); err != nil {
		return false, errors.Join(err, f.Truncate(int64(len(data))))
	}
	return true, f.Sync()
}
