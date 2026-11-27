package sopsx

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRequiresVerifiedBytesBeforeReplacing(t *testing.T) {
	const data = "test release"
	sum := sha256.Sum256([]byte(data))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checksums" {
			fmt.Fprintf(w, "%x  test-asset\n", sum)
			return
		}
		io.WriteString(w, data)
	}))
	defer server.Close()
	a := asset{Name: "test-asset", URL: server.URL, Size: int64(len(data))}
	if _, err := expectedDigest(server.Client(), "3.9.0", a, asset{}); err == nil {
		t.Fatal("missing digest was accepted")
	}
	manifest := asset{URL: server.URL + "/checksums"}
	if _, err := expectedDigest(server.Client(), DefaultVersion, a, manifest); err == nil {
		t.Fatal("default release accepted a different checksum manifest")
	}
	want, err := expectedDigest(server.Client(), "3.9.0", a, manifest)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, exeName())
	if err := os.WriteFile(dest, []byte("installed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := installAsset(server.Client(), dir, a, make([]byte, sha256.Size)); err == nil {
		t.Fatal("wrong digest was accepted")
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != "installed" {
		t.Fatal("failed download altered the existing executable")
	}
	if _, err := installAsset(server.Client(), dir, a, want); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != data {
		t.Fatal("verified executable was not installed")
	}
}
