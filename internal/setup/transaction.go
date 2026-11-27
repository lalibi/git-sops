package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/worktree"
)

func prepareLockedIndex(g *gitx.Git, index string, dst *os.File) error {
	src, err := os.Open(index)
	if err != nil {
		closeErr := dst.Close()
		// An unborn repository can have a policy before its first git add.
		if errors.Is(err, os.ErrNotExist) && closeErr == nil {
			_, err = g.Run(nil, "read-tree", "--empty")
		}
		return errors.Join(err, closeErr)
	}
	info, err := src.Stat()
	if err == nil {
		err = dst.Chmod(info.Mode().Perm())
	}
	if err == nil {
		_, err = io.Copy(dst, src)
	}
	return errors.Join(err, src.Close(), dst.Close())
}

// Stage and verify against a private copy under Git's normal index lock. Publish
// it with a rename. A failed operation never restores an old index over another
// process's staged changes.
func pathTransaction(e *Env, work func() error) error {
	index, err := e.Git.Output("rev-parse", "--path-format=absolute", "--git-path", "index")
	if err != nil {
		return err
	}
	lock := index + ".lock"
	dst, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("lock Git index: %w", err)
	}
	published := false
	defer func() {
		if !published {
			os.Remove(lock)
		}
	}()
	g := *e.Git
	g.IndexFile = lock
	if err := prepareLockedIndex(&g, index, dst); err != nil {
		return err
	}
	originalGit := e.Git
	e.Git = &g
	defer func() {
		e.Git = originalGit
		e.beforeWorkWrite = nil
	}()
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}

	// Back up a working file only when we will overwrite it. Most recipient
	// changes touch ciphertext in the index while local plaintext stays intact.
	type snapshot struct {
		data   []byte
		mode   os.FileMode
		exists bool
	}
	saved := map[string]snapshot{}
	save := func(p string) error {
		if _, ok := saved[p]; ok {
			return nil
		}
		st, err := os.Lstat(filepath.Join(e.Root, filepath.FromSlash(p)))
		if errors.Is(err, os.ErrNotExist) {
			saved[p] = snapshot{}
			return nil
		}
		if err != nil {
			return err
		}
		b, err := worktree.ReadFile(e.Root, p)
		if err == nil {
			saved[p] = snapshot{data: b, mode: st.Mode().Perm(), exists: true}
		}
		return err
	}
	for _, path := range []string{".sops.yaml", ".gitattributes"} {
		if err := save(path); err != nil {
			return err
		}
	}
	e.beforeWorkWrite = save
	if err = work(); err == nil {
		err = os.Rename(lock, index)
		published = err == nil
	}
	if err != nil {
		for p, original := range saved {
			if original.exists {
				err = errors.Join(err, worktree.WriteFile(e.Root, p, original.data, original.mode))
			} else {
				root, openErr := os.OpenRoot(e.Root)
				if openErr != nil {
					err = errors.Join(err, openErr)
					continue
				}
				removeErr := root.Remove(filepath.FromSlash(p))
				root.Close()
				if !errors.Is(removeErr, os.ErrNotExist) {
					err = errors.Join(err, removeErr)
				}
			}
		}
	}
	return err
}
