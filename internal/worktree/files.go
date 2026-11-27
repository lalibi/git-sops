// Package worktree handles files that Git expects to be regular working-tree
// entries. Git stores a symlink's target name, so a linked path must never be
// treated as a destination for decrypted bytes or generated configuration.
package worktree

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func fileRoot(dir, name string) (*os.Root, error) {
	if !filepath.IsLocal(name) || name == "." || filepath.Clean(name) != name {
		return nil, fmt.Errorf("expected a repository-relative file: %q", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	for p := name; p != "."; p = filepath.Dir(p) {
		if strings.EqualFold(filepath.Base(p), ".git") {
			root.Close()
			return nil, fmt.Errorf("refusing to access Git metadata at %q", name)
		}
		info, err := root.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			root.Close()
			return nil, err
		}
		if (p == name && !info.Mode().IsRegular()) || (p != name && !info.IsDir()) || info.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, fmt.Errorf("expected a regular file and directory parents for %q", name)
		}
	}
	return root, nil
}

func Open(dir, path string) (*os.File, error) {
	name := filepath.FromSlash(path)
	root, err := fileRoot(dir, name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(name)
}

func ReadFile(dir, path string) ([]byte, error) {
	name := filepath.FromSlash(path)
	root, err := fileRoot(dir, name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

func WriteFile(dir, path string, data []byte, perm os.FileMode) error {
	name := filepath.FromSlash(path)
	root, err := fileRoot(dir, name)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	return root.WriteFile(name, data, perm)
}
