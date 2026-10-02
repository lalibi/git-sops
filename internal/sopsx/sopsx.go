// Package sopsx locates, installs and drives the sops executable.
package sopsx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Client struct {
	Exe string
	// Dir is the working directory; sops resolves .sops.yaml relative to it.
	Dir string
	// KeyFile is exported as SOPS_AGE_KEY_FILE when the caller has not set a key.
	KeyFile string
}

type Types struct {
	Plain     string
	Encrypted string
}

// TypesFor maps a path to the SOPS input/output formats. Unknown extensions are
// handled as binary, which SOPS stores in its JSON envelope.
func TypesFor(path string) Types {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return Types{"json", "json"}
	case ".yaml", ".yml":
		return Types{"yaml", "yaml"}
	case ".env":
		return Types{"dotenv", "dotenv"}
	case ".ini":
		return Types{"ini", "ini"}
	default:
		return Types{"binary", "json"}
	}
}

func (c *Client) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(c.Exe, args...)
	cmd.Dir = c.Dir
	cmd.Stdin = bytes.NewReader(stdin)

	cmd.Env = os.Environ()
	if c.KeyFile != "" && os.Getenv("SOPS_AGE_KEY_FILE") == "" && os.Getenv("SOPS_AGE_KEY") == "" {
		cmd.Env = append(cmd.Env, "SOPS_AGE_KEY_FILE="+c.KeyFile)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	return stdout.Bytes(), nil
}

func (c *Client) Encrypt(path string, plain []byte) ([]byte, error) {
	t := TypesFor(path)
	return c.run(plain,
		"encrypt",
		"--filename-override", path,
		"--input-type", t.Plain,
		"--output-type", t.Encrypted)
}

func (c *Client) Decrypt(path string, encrypted []byte) ([]byte, error) {
	t := TypesFor(path)
	return c.run(encrypted,
		"decrypt",
		"--filename-override", path,
		"--input-type", t.Encrypted,
		"--output-type", t.Plain)
}

// IsEncrypted reports whether blob is valid SOPS ciphertext. filestatus only
// accepts a file argument, so the blob goes through a temporary file.
func (c *Client) IsEncrypted(path string, blob []byte) bool {
	tmp, err := os.CreateTemp("", "sops-check-*"+filepath.Ext(path))
	if err != nil {
		return false
	}
	defer os.Remove(tmp.Name())

	_, writeErr := tmp.Write(blob)
	closeErr := tmp.Close()
	if writeErr != nil || closeErr != nil {
		return false
	}

	out, err := c.run(nil, "filestatus", "--input-type", TypesFor(path).Encrypted, tmp.Name())
	if err != nil {
		return false
	}

	var status struct {
		Encrypted bool `json:"encrypted"`
	}
	if json.Unmarshal(out, &status) != nil {
		return false
	}
	return status.Encrypted
}

func (c *Client) Version() (string, error) {
	out, err := c.run(nil, "--version")
	if err != nil {
		return "", err
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	return strings.TrimSuffix(first, " (latest)"), nil
}

// InstallDir is where Install places sops; Find also looks here so PATH edits are unnecessary.
func InstallDir() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("LOCALAPPDATA is not set")
		}
		return filepath.Join(base, "git-sops", "bin"), nil
	}

	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "git-sops", "bin"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "git-sops", "bin"), nil
}

func exeName() string {
	if runtime.GOOS == "windows" {
		return "sops.exe"
	}
	return "sops"
}

// Find returns the sops executable from PATH or the git-sops install directory.
func Find() (string, error) {
	if p, err := exec.LookPath("sops"); err == nil {
		return p, nil
	}

	var candidates []string
	if dir, err := InstallDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, exeName()))
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			candidates = append(candidates, filepath.Join(base, "Programs", "SOPS", "sops.exe"))
		}
	}

	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}

	return "", fmt.Errorf("sops was not found; run 'git-sops install-sops' or install it with your package manager")
}
