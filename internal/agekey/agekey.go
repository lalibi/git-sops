// Package agekey manages the local age identity used by SOPS.
package agekey

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		return nil, fmt.Errorf("invalid age identity in %q", path)
	}

	return &Identity{KeyFile: path, Recipient: id.Recipient().String()}, nil
}

// LocalRecipients includes all native age identities SOPS can load from its key file or environment.
func LocalRecipients() ([]string, error) {
	path, err := KeyFile()
	if err != nil {
		return nil, err
	}
	lines, err := readSecretLines(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lines = append(lines, strings.Split(os.Getenv("SOPS_AGE_KEY"), "\n")...)
	var keys []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, secretPrefix) {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, errors.New("invalid local age identity")
		}
		keys = append(keys, id.Recipient().String())
	}
	return keys, nil
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

	f, err := openPrivate(path, true)
	if err != nil {
		return nil, err
	}

	content := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), id.Recipient(), id)
	_, writeErr := f.WriteString(content)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, errors.Join(err, os.Remove(path))
	}

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

	var additions strings.Builder
	for _, s := range secrets {
		if _, err := age.ParseX25519Identity(s); err != nil {
			return fmt.Errorf("invalid age identity in %q", source)
		}
		if !have[s] {
			fmt.Fprintf(&additions, "\n%s\n", s)
			have[s] = true
		}
	}
	f, err := openPrivate(dest, false)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(additions.String())
	return errors.Join(writeErr, f.Close())
}
