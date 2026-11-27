# git-sops

Edit a secret as an ordinary file. When you run `git add`, Git sends it through SOPS and stages the encrypted version. On checkout, collaborators with the matching age key get the working file back. This works with text configuration, certificates and binary backups on Windows, Linux and macOS.

## Install

Download a binary for your platform from the [releases page](https://github.com/lalibi/git-sops/releases), or build the latest published version with Go 1.27 or newer.

```sh
go install github.com/lalibi/git-sops/cmd/git-sops@latest
```

You need Git 2.55 or newer for config-based hooks, and a SOPS executable. If you manage SOPS separately, put it on your `PATH`. Otherwise run `git-sops install-sops`. Use `git-sops check` to see which executable and age identity this clone uses.

## Protect your first file

From a Git repository containing the files you want to protect, run:

```sh
git-sops init --protect secrets/
git-sops status --protected
git-sops verify
git diff --cached --stat
git commit -m "Protect secrets with SOPS"
```

`init` creates a local age identity if needed. It writes the path and public recipient rules to `.gitattributes` and `.sops.yaml`, configures this clone’s filters and pre-commit hook, and stages the files. Back up your private identity outside the repository. Losing the last authorized key means losing the ability to decrypt those files.

To add one more file later, run `git-sops protect path/to/file`. A normal `git add` handles subsequent edits. To see exactly what the next commit will store for a file, use `git cat-file blob :path/to/file`. Git’s normal diff driver can show decrypted values.

## Give someone access

1. The collaborator clones the repository and runs `git-sops join`. If they need a new identity, the command generates one, prints its public `age1…` key, and exits with code 2.
2. A maintainer runs `git-sops add-recipient <public-age-key> --commit`, reviews the commit, and pushes it.
3. The collaborator pulls that commit and runs `git-sops join` again.

Repositories using v0.3.2 share one recipient list. The development version also supports named groups for individual paths. Run `git-sops access` to list the public keys and their file counts, or supply one public key to see its files. Existing shared policies work across both versions. Upgrade clients and CI before enabling a named group. [Policy examples and compatibility](docs/policies.md#named-recipient-groups)

## Security and operations

Structured SOPS files expose field names. Paths, commit messages, public recipients and earlier versions remain visible in Git. A trusted checkout can contain plaintext in files, diffs and build output. Review the policy and run `git-sops verify` in CI if you rely on it for contributor changes. [Security model and reporting](SECURITY.md)

| Task | Guide |
| --- | --- |
| Select paths, assign groups or inspect file formats | [Paths and recipients](docs/policies.md) |
| Move machines, grant or revoke access, use worktrees or troubleshoot filters | [Working with an encrypted repository](docs/operations.md) |
| Migrate git-crypt files or rewrite an existing history | [Migration and recovery](docs/migration.md) |

## Build and test

```sh
go build -o bin/ ./cmd/git-sops
go vet ./...
go test -count=1 -timeout 30m ./...
```

The CLI tests create temporary repositories and use real Git and SOPS. Install both to run these tests. The mixed-version test also needs the local `v0.3.2` Git tag. CI runs the suite on all three supported operating systems.

Command and flag definitions live in `cmd/git-sops`. For filter and index behavior, start in `internal/filter`. For policy parsing, see `internal/config`. Clone setup, recipient changes, migration and history operations live in separate files under `internal/setup`. `internal/sopsx` runs the SOPS executable.

Maintainers can preview release archives with `goreleaser release --snapshot --clean`. Pushing a version tag triggers the test matrix and, once it passes, builds the archives and publishes their checksums.

[MIT license](LICENSE)
