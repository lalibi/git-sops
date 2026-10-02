// Package agekey manages the local age identity used by SOPS.
package agekey

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
)

const secretPrefix = "AGE-SECRET-KEY-"

type Identity struct {
	KeyFile   string
	Recipient string
}

// KeyFile returns the key location SOPS uses: SOPS_AGE_KEY_FILE, else <UserConfigDir>/sops/age/keys.txt.
func KeyFile() (string, error) {
	if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
		return p, nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sops", "age", "keys.txt"), nil
}

func readSecretLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var secrets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, secretPrefix) {
			secrets = append(secrets, line)
		}
	}
	return secrets, sc.Err()
}

// Load returns the identity in the key file, or nil when none exists.
func Load() (*Identity, error) {
	path, err := KeyFile()
	if err != nil {
		return nil, err
	}

	secrets, err := readSecretLines(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, nil
	}

	id, err := age.ParseX25519Identity(secrets[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse the age identity in '%s': %w", path, err)
	}

	return &Identity{KeyFile: path, Recipient: id.Recipient().String()}, nil
}

// Generate creates a new identity file. It refuses to touch an existing file.
func Generate() (*Identity, error) {
	path, err := KeyFile()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}

	content := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), id.Recipient(), id)
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	Protect(path)
	return &Identity{KeyFile: path, Recipient: id.Recipient().String()}, nil
}

// Import appends the secret keys from source to the key file, skipping ones already present.
func Import(source string) error {
	secrets, err := readSecretLines(source)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		return fmt.Errorf("no %s identity was found in '%s'", secretPrefix, source)
	}

	dest, err := KeyFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}

	existing, err := readSecretLines(dest)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	have := map[string]bool{}
	for _, s := range existing {
		have[s] = true
	}

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, s := range secrets {
		if !have[s] {
			if _, err := fmt.Fprintf(f, "\n%s\n", s); err != nil {
				return err
			}
		}
	}

	Protect(dest)
	return nil
}

// Protect restricts the key file to the current user.
func Protect(path string) {
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
		return
	}

	u, err := user.Current()
	if err != nil {
		return
	}

	// Best effort: a failure leaves the inherited ACL in place.
	if exec.Command("icacls.exe", path, "/inheritance:r").Run() == nil {
		_ = exec.Command("icacls.exe", path, "/grant:r", u.Username+":(F)").Run()
	}
}
