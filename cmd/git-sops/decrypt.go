package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

func newDecryptCommand() *cobra.Command {
	var recursive, inPlace bool

	cmd := &cobra.Command{
		Use:   "decrypt <path>...",
		Short: "Decrypt SOPS-encrypted files without Git (to stdout, or in place)",
		Long: `Decrypt files that git-sops stores in a repository, without needing Git or the
repository filter. Useful in CI or deploy scripts that only have the age key.

Without --in-place a single file is written to stdout. With --in-place every
encrypted file is overwritten with its plaintext; directories need --recursive.
Files that are not SOPS ciphertext are skipped when walking a directory.`,
		Example: `  git-sops decrypt secrets/db.json
  git-sops decrypt --in-place --recursive secrets/`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDecrypt(args, recursive, inPlace)
		},
	}
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "descend into directories (requires --in-place)")
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "overwrite the files with their plaintext")
	return cmd
}

func runDecrypt(paths []string, recursive, inPlace bool) error {
	sopsExe, err := sopsx.Find()
	if err != nil {
		return err
	}
	keyFile, _ := agekey.KeyFile()
	client := &sopsx.Client{Exe: sopsExe, KeyFile: keyFile}

	if !inPlace {
		if recursive || len(paths) != 1 {
			return errors.New("decrypting to stdout takes exactly one file; use --in-place for several files or directories")
		}
		return decryptToStdout(client, paths[0])
	}

	files, err := expandFiles(paths, recursive)
	if err != nil {
		return err
	}

	explicit := map[string]bool{}
	for _, p := range paths {
		explicit[p] = true
	}

	decrypted, skipped := 0, 0
	for _, f := range files {
		blob, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		if !client.IsEncrypted(f, blob) {
			if explicit[f] {
				return fmt.Errorf("'%s' is not SOPS ciphertext", f)
			}
			skipped++
			continue
		}

		plain, err := client.Decrypt(f, blob)
		if err != nil {
			return fmt.Errorf("could not decrypt '%s': %w", f, err)
		}
		// WriteFile keeps the mode of an existing file.
		if err := os.WriteFile(f, plain, 0o600); err != nil {
			return err
		}
		decrypted++
	}

	ui.Okf("Decrypted %d file(s)", decrypted)
	if skipped > 0 {
		ui.Printf("  %s", ui.Dim(fmt.Sprintf("%d file(s) were not SOPS ciphertext and were left alone", skipped)))
	}
	return nil
}

func decryptToStdout(client *sopsx.Client, path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("'%s' is a directory; use --in-place --recursive", path)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, err := client.Decrypt(path, blob)
	if err != nil {
		return fmt.Errorf("could not decrypt '%s': %w", path, err)
	}
	_, err = os.Stdout.Write(plain)
	return err
}

// expandFiles lists the regular files under paths, skipping .git directories.
func expandFiles(paths []string, recursive bool) ([]string, error) {
	var files []string

	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			files = append(files, p)
			continue
		}
		if !recursive {
			return nil, fmt.Errorf("'%s' is a directory; pass --recursive", p)
		}

		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == ".git" {
				return filepath.SkipDir
			}
			if d.Type().IsRegular() {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
