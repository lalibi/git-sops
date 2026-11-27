// Package check reports whether the machine and the current repository are ready to use git-sops.
package check

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/filter"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

type report struct{ failed, warned bool }

func (r *report) row(status ui.Status, label, value string, details ...string) {
	if status == ui.StatusFail {
		r.failed = true
	} else if status == ui.StatusWarn {
		r.warned = true
	}
	ui.Row(status, label, value, details...)
}

// Run prints the environment status and, inside a repository, the repository status.
// It returns an exit-code error when something required is missing or broken.
func Run(repoPath string) error {
	r := &report{}

	ui.Header("check", "")
	ui.Section("Environment")

	g, sopsExe := environment(r)
	id, err := agekey.Load()
	if err != nil {
		r.row(ui.StatusFail, "age identity", "could not load key file", err.Error())
	} else {
		identity(r, id)
	}

	if g != nil {
		if root, err := gitx.ToplevelOf(g.Exe, repoPath); err == nil {
			ui.Section("Repository  " + ui.Dim(root))
			g.Dir = root
			repository(r, g, sopsExe, root, id)
		}
	}

	ui.Printf("")
	if r.failed {
		return &setup.ExitCodeError{Code: 1}
	}
	if r.warned {
		ui.Warnf("Check completed with warnings")
	} else {
		ui.Okf("Everything looks good")
	}
	return nil
}

func environment(r *report) (*gitx.Git, string) {
	g, err := gitx.New("")
	if err != nil {
		r.row(ui.StatusFail, "Git", "not found", "Install Git "+gitx.FormatVersion(gitx.MinimumVersion)+" or newer.")
		g = nil
	} else if v, err := g.Version(); err != nil {
		r.row(ui.StatusFail, "Git", err.Error())
	} else if !gitx.VersionAtLeast(v, gitx.MinimumVersion) {
		r.row(ui.StatusFail, "Git", gitx.FormatVersion(v),
			"Version "+gitx.FormatVersion(gitx.MinimumVersion)+" or newer is required for config-based hooks.")
	} else {
		r.row(ui.StatusOK, "Git", gitx.FormatVersion(v))
	}

	sopsExe, err := sopsx.Find()
	if err != nil {
		r.row(ui.StatusFail, "SOPS", "not found",
			"Run `git-sops install-sops`, or install it with your package manager.")
		return g, ""
	}

	version, err := (&sopsx.Client{Exe: sopsExe}).Version()
	if err != nil {
		r.row(ui.StatusFail, "SOPS", "failed to run", sopsExe, err.Error())
		return g, ""
	}
	r.row(ui.StatusOK, "SOPS", version, sopsExe)
	return g, sopsExe
}

func identity(r *report, id *agekey.Identity) {
	if id == nil {
		r.row(ui.StatusInfo, "age identity", "none yet", "`git-sops init` or `git-sops join` creates one.")
		return
	}
	r.row(ui.StatusOK, "age identity", id.Recipient, id.KeyFile)
}

func repository(r *report, g *gitx.Git, sopsExe, root string, id *agekey.Identity) {
	data, err := os.ReadFile(filepath.Join(root, ".sops.yaml"))
	var managed *config.Managed
	if err == nil {
		managed, err = config.ParseManaged(data)
	}
	clean, _ := g.Output("config", "--local", "--get", "filter.sops.clean")

	if clean == "" && managed == nil && (err == nil || errors.Is(err, os.ErrNotExist)) {
		r.row(ui.StatusInfo, "git-sops", "not set up here", "Run `git-sops init` to protect files in this repository.")
		return
	}

	switch {
	case errors.Is(err, os.ErrNotExist):
		r.row(ui.StatusFail, ".sops.yaml", "missing", "Restore the repository's SOPS creation rules before encrypting new files.")
	case err != nil:
		r.row(ui.StatusFail, ".sops.yaml", "could not read policy", err.Error())
	case managed == nil:
		r.row(ui.StatusWarn, ".sops.yaml", "no git-sops management header",
			"For a custom policy, manage creation rules and recipients in .sops.yaml. The recipient check was skipped.")
	default:
		count := fmt.Sprintf("%d recipient(s)", len(managed.Recipients))
		if managed.Groups != nil {
			count = fmt.Sprintf("%d recipient group(s)", len(managed.Groups))
		}
		r.row(ui.StatusOK, ".sops.yaml",
			count,
			"protects: "+strings.Join(managed.ProtectedPaths, ", "))
	}

	filterConfig(r, g, clean)
	hookConfig(r, g)

	if id != nil && managed != nil {
		if managed.Groups == nil {
			authorized(r, id, managed)
		} else {
			n := 0
			for _, rule := range managed.ProtectedPaths {
				if slices.Contains(managed.KeysForRule(rule), id.Recipient) {
					n++
				}
			}
			r.row(ui.StatusInfo, "Access", fmt.Sprintf("this identity is listed for %d of %d rules", n, len(managed.ProtectedPaths)), "Use git-sops access "+id.Recipient+" to list effective paths.")
		}
	}
	if managed != nil {
		for _, group := range managed.GroupNames() {
			if len(managed.Groups[group]) == 1 {
				r.row(ui.StatusWarn, "Recovery", "group "+group+" has one recipient", "Add a second maintainer or an offline recovery recipient to this group if required.")
			}
		}
	}

	if sopsExe != "" {
		indexCheck(r, g, sopsExe)
	}
}

func filterConfig(r *report, g *gitx.Git, clean string) {
	smudge, _ := g.Output("config", "--local", "--get", "filter.sops.smudge")
	required, _ := g.Output("config", "--local", "--get", "filter.sops.required")

	if clean == "" || smudge == "" {
		r.row(ui.StatusFail, "Git filter", "not configured", "Run `git-sops join` to configure this clone.")
		return
	}

	for _, cmd := range []string{clean, smudge} {
		if exe := commandExecutable(cmd); !resolves(exe) {
			r.row(ui.StatusFail, "Git filter", "executable is missing", exe,
				"Run `git-sops join` to point the filter at the current binary.")
			return
		}
	}

	if required != "true" {
		r.row(ui.StatusWarn, "Git filter", "configured but not required", "A missing filter would silently commit plaintext.")
		return
	}
	r.row(ui.StatusOK, "Git filter", "configured", clean)
}

func hookConfig(r *report, g *gitx.Git) {
	hooks, err := g.Output("hook", "list", "--show-scope", "pre-commit")
	if err != nil || !strings.Contains(hooks, "sops-index") {
		r.row(ui.StatusFail, "Pre-commit hook", "not configured", "Run `git-sops join`.")
		return
	}

	command, _ := g.Output("config", "--local", "--get", "hook.sops-index.command")
	if exe := commandExecutable(command); !resolves(exe) {
		r.row(ui.StatusFail, "Pre-commit hook", "executable is missing", exe, "Run `git-sops join`.")
		return
	}
	r.row(ui.StatusOK, "Pre-commit hook", "sops-index", command)
}

func authorized(r *report, id *agekey.Identity, managed *config.Managed) {
	for _, rec := range managed.Recipients {
		if rec == id.Recipient {
			r.row(ui.StatusOK, "Access", "this machine's key is a recipient")
			return
		}
	}

	r.row(ui.StatusWarn, "Access", "this machine's key is not a recipient",
		"Send your recipient to a maintainer, who runs `git-sops add-recipient "+id.Recipient+"`.")
}

func indexCheck(r *report, g *gitx.Git, sopsExe string) {
	keyFile, _ := agekey.KeyFile()
	checked, failures, err := filter.VerifyIndex(g, &sopsx.Client{Exe: sopsExe, Dir: g.Dir, KeyFile: keyFile})

	switch {
	case err != nil:
		r.row(ui.StatusFail, "Index", err.Error())
	case len(failures) > 0:
		r.row(ui.StatusFail, "Index", fmt.Sprintf("%d of %d protected file(s) are not encrypted", len(failures), checked), failures...)
	case checked == 0:
		r.row(ui.StatusInfo, "Index", "no protected files tracked yet")
	default:
		r.row(ui.StatusOK, "Index", fmt.Sprintf("%d protected file(s) have SOPS metadata", checked))
	}
}

// commandExecutable extracts the program from a filter command such as `'C:/x/git-sops.exe' clean %f`.
func commandExecutable(command string) string {
	command = strings.TrimSpace(command)
	if strings.HasPrefix(command, "'") {
		if end := strings.Index(command[1:], "'"); end >= 0 {
			return command[1 : 1+end]
		}
	}
	if fields := strings.Fields(command); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func resolves(exe string) bool {
	if exe == "" {
		return false
	}
	if filepath.IsAbs(exe) {
		_, err := os.Stat(exe)
		return err == nil
	}
	_, err := exec.LookPath(exe)
	return err == nil
}
