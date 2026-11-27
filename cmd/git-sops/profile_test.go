package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
)

func TestInstallProfilePreservesExistingContent(t *testing.T) {
	const text = "# café\r\n$existing = 42"
	block := profileBlock("C:/O'Brien/git-sops.exe")
	for _, tc := range []struct {
		name, bom string
		enc       encoding.Encoding
	}{
		{"UTF-8", "", encoding.Nop},
		{"UTF-8 BOM", "\xef\xbb\xbf", encoding.Nop},
		{"Windows PowerShell UTF-16", "\xff\xfe", unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.ps1")
			original, err := tc.enc.NewEncoder().String(text)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.bom+original), 0600); err != nil {
				t.Fatal(err)
			}
			if added, err := installProfileBlock(path, block); err != nil || !added {
				t.Fatalf("install: %v, %v", added, err)
			}
			want, err := tc.enc.NewEncoder().String(text + "\r\n" + strings.ReplaceAll(block, "\n", "\r\n") + "\r\n")
			if err != nil {
				t.Fatal(err)
			}
			if added, err := installProfileBlock(path, block); err != nil || added {
				t.Fatalf("repeat: %v, %v", added, err)
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, []byte(tc.bom+want)) {
				t.Fatalf("unexpected profile bytes: %x, %v", got, err)
			}
		})
	}
}

func TestInstallProfileRejectsBrokenMarkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.ps1")
	for _, text := range []string{profileBegin, profileEnd, profileEnd + "\n" + profileBegin, profileBlock("gs") + "\n" + profileBlock("gs")} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := installProfileBlock(path, profileBlock("gs")); err == nil {
			t.Fatal("accepted broken markers")
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != text {
			t.Fatal("changed malformed profile")
		}
	}
}
