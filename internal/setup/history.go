package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/filter"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

// EncryptHistory builds and validates new objects in an isolated mirror, then swaps
// the source refs in a single compare-and-swap transaction. It never pushes.
func EncryptHistory(o Options, approved bool) error {
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}
	m, err := managedPolicy(e)
	if err != nil {
		return err
	}
	specs, err := config.BuildSpecs(e.Root, append(m.ProtectedPaths, o.Protect...))
	if err != nil {
		return err
	}
	paths := specPaths(specs)
	if len(paths) == 0 {
		return errors.New("specify at least one historical path with --protect")
	}
	specs, err = config.BuildSpecs(e.Root, paths)
	if err != nil {
		return err
	}
	if shallow, err := e.Git.Output("rev-parse", "--is-shallow-repository"); err != nil || shallow != "false" {
		return errors.New("history encryption requires a complete, non-shallow repository")
	}
	worktrees, err := e.Git.Output("worktree", "list", "--porcelain")
	if err != nil {
		return err
	}
	if strings.Count(worktrees, "worktree ") != 1 {
		return errors.New("remove linked worktrees before rewriting history")
	}
	refs, err := historyRefs(e.Git)
	if err != nil {
		return err
	}
	tracked, err := e.Git.ZList("ls-files", "-z")
	if err != nil {
		return err
	}
	var attributes []string
	for _, p := range tracked {
		if strings.HasSuffix(p, "/.gitattributes") {
			attributes = append(attributes, p)
		}
	}
	for name := range refs {
		if strings.HasPrefix(name, "refs/replace/") {
			return errors.New("remove replace refs before rewriting history")
		}
	}
	if err := validateHistoryRefTargets(e.Git, refs); err != nil {
		return err
	}
	common, err := e.Git.Output("rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return err
	}
	if b, err := os.ReadFile(filepath.Join(common, "info", "grafts")); err == nil && len(bytes.TrimSpace(b)) > 0 {
		return errors.New("remove legacy grafts before rewriting history")
	}
	head, err := e.Git.Output("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	headRef, symErr := e.Git.Output("symbolic-ref", "-q", "HEAD")
	if symErr == nil && refs[headRef] != head {
		return errors.New("HEAD does not match its branch")
	}
	// Configuration must already be tracked; no untracked file is overwritten at the tip.
	for _, p := range []string{".gitattributes", ".sops.yaml"} {
		if _, err := e.Git.Output("ls-files", "--error-unmatch", "--", p); err != nil {
			return fmt.Errorf("commit %s before rewriting history", p)
		}
	}
	ui.Header("encrypt-history", e.Root)
	ui.Warnf("This rewrites ALL local refs, including branches, remote-tracking refs, tags and checkpoint trees, in place.")
	ui.Warnf("Commit IDs change. Commit and tag signatures are removed. Coordinate force pushes and fresh clones with collaborators.")
	ui.Warnf("Selected paths: %s. Renamed historical paths must be listed explicitly; submodule histories are not traversed.", strings.Join(paths, ", "))
	ui.Warnf("A recovery bundle is retained in the Git directory. It and old unreachable objects contain the ORIGINAL plaintext history.")
	ui.Warnf("Remotes, forks, other clones and hosting caches are unchanged. Rotate any exposed credentials. No push or pruning is performed.")
	if !approved {
		if !ui.Interactive() {
			return errors.New("explicit approval required: rerun interactively, or pass --confirm-rewrite to acknowledge these warnings")
		}
		answer, err := ui.Input("Approve the in-place history rewrite?", "Type 'rewrite history' to approve. Anything else cancels.", "rewrite history", "", nil)
		if err != nil {
			return err
		}
		if answer != "rewrite history" {
			return ui.ErrCancelled
		}
	}
	// Only disposable objects are built until the final ref transaction.
	tmp, err := os.MkdirTemp(common, "git-sops-rewrite-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	mirror := filepath.Join(tmp, "mirror.git")
	if _, err := e.Git.Run(nil, "clone", "--mirror", "--no-local", "--", e.Root, mirror); err != nil {
		return err
	}
	g := &gitx.Git{Exe: e.Git.Exe, Dir: mirror}
	// Include detached HEAD even if no named ref reaches it.
	tempHeadRef := "refs/git-sops-rewrite/" + filepath.Base(tmp)
	if _, exists := refs[tempHeadRef]; exists {
		return errors.New("temporary history ref collision")
	}
	if _, err := g.Run(nil, "fetch", "--no-tags", "--no-write-fetch-head", e.Root, head); err != nil {
		return err
	}
	if _, err := g.Run(nil, "update-ref", tempHeadRef, head); err != nil {
		return err
	}
	policyDir := filepath.Join(tmp, "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		return err
	}
	if err := config.WriteSopsConfig(policyDir, specs, m.Recipients, false, ui.Warnf); err != nil {
		return err
	}
	policy, err := os.ReadFile(filepath.Join(policyDir, ".sops.yaml"))
	if err != nil {
		return err
	}
	r := &historyRewriter{git: g, sops: &sopsx.Client{Exe: e.Sops.Exe, Dir: policyDir, KeyFile: e.Sops.KeyFile}, specs: specs,
		policy: policy, objects: map[string]string{}, trees: map[string]string{}, blobs: map[string]string{}}
	commits, err := g.Output("rev-list", "--reverse", "--topo-order", "--all")
	if err != nil {
		return err
	}
	list := strings.Fields(commits)
	bar := ui.NewProgress("Encrypting history", int64(len(list)), false)
	for i, oid := range list {
		bar.Set(int64(i), oid)
		if err := r.commit(oid); err != nil {
			bar.Abort()
			return err
		}
	}
	bar.Set(int64(len(list)), "")
	bar.Finish("Prepared %d rewritten commits", len(list))
	newRefs := map[string]string{}
	for name, oid := range refs {
		rewritten, err := r.object(oid)
		if err != nil {
			return fmt.Errorf("rewrite %s: %w", name, err)
		}
		newRefs[name] = rewritten
	}
	// A disconnected source ref must never silently retain plaintext history.
	for name, oid := range newRefs {
		if _, err := g.Run(nil, "update-ref", name, oid); err != nil {
			return err
		}
	}
	newHead := r.objects[head]
	if newHead == "" {
		return errors.New("could not rewrite HEAD")
	}
	if _, err := g.Run(nil, "update-ref", tempHeadRef, newHead); err != nil {
		return err
	}
	if _, err := g.Run(nil, "fsck", "--full", "--no-reflogs"); err != nil {
		return err
	}
	current, err := historyRefs(e.Git)
	if err != nil {
		return err
	}
	if !sameRefs(refs, current) {
		return errors.New("refs changed while preparing history; no source refs were rewritten")
	}
	if now, err := e.Git.Output("rev-parse", "HEAD"); err != nil || now != head {
		return errors.New("HEAD changed while preparing history")
	}
	if nowRef, nowErr := e.Git.Output("symbolic-ref", "-q", "HEAD"); (nowErr == nil) != (symErr == nil) || nowRef != headRef {
		return errors.New("HEAD attachment changed while preparing history")
	}
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}
	backup := filepath.Join(common, "git-sops-before-history-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".bundle")
	if _, err := e.Git.Run(nil, "bundle", "create", backup, "--all", "HEAD"); err != nil {
		return err
	}
	if err := os.Chmod(backup, 0o600); err != nil {
		return err
	}
	ui.Warnf("Recovery bundle (contains original history): %s", backup)
	// Fetch objects without changing any source refs, configuration or FETCH_HEAD.
	seen := map[string]bool{}
	for _, oid := range append(refValues(newRefs), newHead) {
		if seen[oid] {
			continue
		}
		seen[oid] = true
		if _, err := e.Git.Run(nil, "fetch", "--no-tags", "--no-write-fetch-head", mirror, oid); err != nil {
			return err
		}
	}
	if err := pathTransaction(e, attributes, func() error {
		if err := swapHistoryRefs(e.Git, refs, newRefs, head, newHead, symErr != nil); err != nil {
			return err
		}
		restore := func(cause error) error {
			return errors.Join(cause, swapHistoryRefs(e.Git, newRefs, refs, newHead, head, symErr != nil))
		}
		if _, err := e.Git.Run(nil, "read-tree", "HEAD"); err != nil {
			return restore(err)
		}
		for _, p := range append(attributes, ".gitattributes", ".sops.yaml") {
			b, err := e.Git.Run(nil, "cat-file", "blob", "HEAD:"+p)
			if err != nil {
				return restore(err)
			}
			if err := os.WriteFile(filepath.Join(e.Root, p), b, 0o644); err != nil {
				return restore(err)
			}
		}
		if err := ConfigureLocal(e); err != nil {
			return restore(err)
		}
		if err := validateSelectedAttributes(e.Git, specs); err != nil {
			return restore(err)
		}
		if err := ValidateIndex(e); err != nil {
			return restore(err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("rewrite failed; recovery bundle: %s: %w", backup, err)
	}
	ui.Okf("History encrypted in place. Review all refs before publishing. No remote was changed.")
	return nil
}

type historyRewriter struct {
	git                   *gitx.Git
	sops                  *sopsx.Client
	specs                 []config.Spec
	policy                []byte
	objects, trees, blobs map[string]string
}

func (r *historyRewriter) write(kind string, data []byte) (string, error) {
	b, err := r.git.Run(data, "hash-object", "-w", "-t", kind, "--stdin")
	return strings.TrimSpace(string(b)), err
}

// rewriteHeaders preserves authors, timestamps, messages and unknown headers.
// Signatures and mergetags refer to old objects and cannot survive a rewrite.
func rewriteHeaders(data []byte, replace func(string, string) (string, error)) ([]byte, error) {
	parts := bytes.SplitN(data, []byte("\n\n"), 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed Git object")
	}
	var out []string
	skip := false
	for _, line := range strings.Split(string(parts[0]), "\n") {
		if strings.HasPrefix(line, " ") {
			if !skip {
				out = append(out, line)
			}
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			return nil, errors.New("malformed Git object header")
		}
		skip = key == "gpgsig" || key == "gpgsig-sha256" || key == "mergetag"
		if skip {
			continue
		}
		val, err := replace(key, val)
		if err != nil {
			return nil, err
		}
		out = append(out, key+" "+val)
	}
	return append([]byte(strings.Join(out, "\n")+"\n\n"), parts[1]...), nil
}

func (r *historyRewriter) commit(oid string) error {
	b, err := r.git.Run(nil, "cat-file", "commit", oid)
	if err != nil {
		return err
	}
	b, err = rewriteHeaders(b, func(key, val string) (string, error) {
		if key == "tree" {
			return r.tree(val, "")
		}
		if key == "parent" {
			if mapped := r.objects[val]; mapped != "" {
				return mapped, nil
			}
			return "", fmt.Errorf("parent %s was not rewritten", val)
		}
		return val, nil
	})
	if err != nil {
		return fmt.Errorf("commit %s: %w", oid, err)
	}
	r.objects[oid], err = r.write("commit", b)
	if err != nil {
		return err
	}
	return r.validateTree(r.objects[oid])
}

// Both commit snapshots and standalone tree refs must satisfy the same policy.
func (r *historyRewriter) validateTree(oid string) error {
	// Use a disposable index in the mirror to validate effective attributes,
	// including historical unmanaged and nested rules.
	if _, err := r.git.Run(nil, "read-tree", oid); err != nil {
		return err
	}
	_, failures, err := filter.VerifyIndex(r.git, r.sops)
	if err != nil {
		return err
	}
	if len(failures) > 0 {
		return fmt.Errorf("snapshot %s still has plaintext protected files: %s; include their paths with --protect", oid, strings.Join(failures, ", "))
	}
	return validateSelectedAttributes(r.git, r.specs)
}

func (r *historyRewriter) object(oid string) (string, error) {
	if mapped := r.objects[oid]; mapped != "" {
		return mapped, nil
	}
	kind, err := r.git.Output("cat-file", "-t", oid)
	if err != nil {
		return "", err
	}
	if kind == "tree" {
		mapped, err := r.tree(oid, "")
		if err != nil {
			return "", err
		}
		if err := r.validateTree(mapped); err != nil {
			return "", err
		}
		r.objects[oid] = mapped
		return mapped, nil
	}
	if kind != "tag" {
		return "", fmt.Errorf("ref targets unsupported %s object %s; only commits, root trees and annotated tags to them are supported", kind, oid)
	}
	b, err := r.git.Run(nil, "cat-file", "tag", oid)
	if err != nil {
		return "", err
	}
	b, err = rewriteHeaders(b, func(key, val string) (string, error) {
		if key == "object" {
			return r.object(val)
		}
		return val, nil
	})
	if err != nil {
		return "", err
	}
	for _, marker := range []string{"\n-----BEGIN PGP SIGNATURE-----", "\n-----BEGIN SSH SIGNATURE-----", "\n-----BEGIN SIGNED MESSAGE-----"} {
		if i := bytes.Index(b, []byte(marker)); i >= 0 {
			b = b[:i+1]
		}
	}
	mapped, err := r.write("tag", b)
	if err == nil {
		r.objects[oid] = mapped
	}
	return mapped, err
}

func (r *historyRewriter) tree(oid, prefix string) (string, error) {
	cacheKey := prefix + "\x00" + oid
	if mapped := r.trees[cacheKey]; mapped != "" {
		return mapped, nil
	}
	entries, err := r.git.ZList("ls-tree", "-z", oid)
	if err != nil {
		return "", err
	}
	var result []string
	foundAttrs, foundPolicy := false, false
	for _, entry := range entries {
		header, name, ok := strings.Cut(entry, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 {
			return "", errors.New("malformed tree entry")
		}
		mode, kind, blob := fields[0], fields[1], fields[2]
		path := prefix + name
		if kind == "tree" {
			blob, err = r.tree(blob, path+"/")
		} else if name == ".gitattributes" {
			if config.Protected(r.specs, path) {
				return "", fmt.Errorf("configuration file %q is inside a protected directory; move it outside the protected path", path)
			}
			if kind != "blob" || mode == "120000" {
				return "", fmt.Errorf("unsupported attributes entry %q", path)
			}
			foundAttrs = true
			original, readErr := r.git.Run(nil, "cat-file", "blob", blob)
			if readErr != nil {
				return "", readErr
			}
			var rendered []byte
			rendered, err = config.RenderAttributes(original, relativeSpecs(r.specs, prefix), false)
			if err == nil {
				blob, err = r.write("blob", rendered)
			}
		} else if prefix == "" && name == ".sops.yaml" {
			if mode == "120000" || kind != "blob" {
				return "", errors.New("unsupported .sops.yaml entry")
			}
			foundPolicy = true
			blob, err = r.write("blob", r.policy)
		} else if config.Protected(r.specs, path) {
			if kind != "blob" || mode == "120000" {
				return "", fmt.Errorf("cannot encrypt symlink or submodule %q", path)
			}
			blob, err = r.encryptBlob(blob, path)
		}
		if err != nil {
			return "", err
		}
		result = append(result, mode+" "+kind+" "+blob+"\t"+name+"\x00")
	}
	if prefix == "" && !foundAttrs {
		attrs, err := config.RenderAttributes(nil, r.specs, false)
		if err != nil {
			return "", err
		}
		blob, err := r.write("blob", attrs)
		if err != nil {
			return "", err
		}
		result = append(result, "100644 blob "+blob+"\t.gitattributes\x00")
	}
	if prefix == "" && !foundPolicy {
		blob, err := r.write("blob", r.policy)
		if err != nil {
			return "", err
		}
		result = append(result, "100644 blob "+blob+"\t.sops.yaml\x00")
	}
	b, err := r.git.Run([]byte(strings.Join(result, "")), "mktree", "-z")
	if err != nil {
		return "", err
	}
	mapped := strings.TrimSpace(string(b))
	r.trees[cacheKey] = mapped
	return mapped, nil
}

func relativeSpecs(specs []config.Spec, prefix string) []config.Spec {
	if prefix == "" {
		return specs
	}
	var out []config.Spec
	for _, s := range specs {
		if s.IsDirectory && strings.HasPrefix(prefix, s.RelativePath+"/") {
			s.AttributePattern = "/**"
			out = append(out, s)
		} else if strings.HasPrefix(s.RelativePath, prefix) {
			rel := strings.TrimPrefix(s.RelativePath, prefix)
			if s.IsDirectory {
				rel += "/"
			}
			built, _ := config.BuildSpecs("", []string{rel})
			if len(built) == 1 {
				s.AttributePattern = built[0].AttributePattern
				out = append(out, s)
			}
		}
	}
	return out
}

func (r *historyRewriter) encryptBlob(oid, path string) (string, error) {
	key := path + "\x00" + oid
	if mapped := r.blobs[key]; mapped != "" {
		return mapped, nil
	}
	plain, err := r.git.Run(nil, "cat-file", "blob", oid)
	if err != nil {
		return "", err
	}
	if r.sops.IsEncrypted(path, plain) {
		plain, err = r.sops.Decrypt(path, plain)
		if err != nil {
			return "", fmt.Errorf("decrypt historical %q: %w", path, err)
		}
	}
	cipher, err := r.sops.Encrypt(path, plain)
	if err != nil {
		return "", fmt.Errorf("encrypt historical %q: %w", path, err)
	}
	verified, err := r.sops.Decrypt(path, cipher)
	if err != nil {
		return "", fmt.Errorf("verify historical %q: %w", path, err)
	}
	if sopsx.TypesFor(path).Plain == "binary" && !bytes.Equal(verified, plain) {
		return "", fmt.Errorf("history encryption changed contents of %q", path)
	}
	mapped, err := r.write("blob", cipher)
	if err == nil {
		r.blobs[key] = mapped
	}
	return mapped, err
}

func historyRefs(g *gitx.Git) (map[string]string, error) {
	out, err := g.Output("for-each-ref", "--format=%(refname) %(objectname) %(symref)")
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			refs[f[0]] = f[1]
		} // Symbolic refs follow their rewritten target.
	}
	return refs, nil
}

// Reject pathless blobs before preparing commits or asking for rewrite approval.
// A tree is interpreted as a repository-root snapshot, including Codex checkpoints.
func validateHistoryRefTargets(g *gitx.Git, refs map[string]string) error {
	for name, oid := range refs {
		kind, err := g.Output("cat-file", "-t", oid+"^{}")
		if err != nil {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
		if kind != "commit" && kind != "tree" {
			return fmt.Errorf("ref %s targets unsupported %s object %s; a standalone blob has no filename for selecting protection rules; no refs were rewritten", name, kind, oid)
		}
	}
	return nil
}

func sameRefs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, oid := range a {
		if b[name] != oid {
			return false
		}
	}
	return true
}

func refValues(refs map[string]string) []string {
	var out []string
	for _, oid := range refs {
		out = append(out, oid)
	}
	return out
}

func swapHistoryRefs(g *gitx.Git, old, new map[string]string, oldHead, newHead string, detached bool) error {
	var input strings.Builder
	input.WriteString("start\n")
	for name, oid := range old {
		fmt.Fprintf(&input, "update %s %s %s\n", name, new[name], oid)
	}
	if detached {
		fmt.Fprintf(&input, "update HEAD %s %s\n", newHead, oldHead)
	}
	input.WriteString("prepare\ncommit\n")
	_, err := g.Run([]byte(input.String()), "update-ref", "--stdin")
	return err
}
