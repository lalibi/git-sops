# Working with an encrypted repository

## Preparing commits

To inspect the Git index, run `git-sops status`. You can limit the check to repository-root-relative files, directories, or quoted patterns:

```powershell
git-sops status secrets/ observability/portal.env
git-sops status --protected '**/*.env'
```

`'*.env'` selects root-level files and `'**/*.env'` includes subdirectories. Counts and the exit status apply to the selected tracked files. The `--protected` and `--unprotected` flags filter the displayed rows and still count issues in the selection.

`init`, `protect`, `unprotect`, `add-recipient`, `remove-recipient`, and `migrate-git-crypt` stage their repository changes by default. Add `--commit` to create a commit after encryption and validation:

```powershell
git-sops init --protect "secrets/,Web.config" --commit
git-sops protect src/Worker/service-secrets.txt --commit
git-sops unprotect examples/ --commit
git-sops add-recipient age1... --commit
git-sops remove-recipient age1... --commit
git-sops migrate-git-crypt --protect secrets/ --commit
```

With `--commit`, the index and tracked working tree must be clean before the operation starts. Finish any active merge, rebase, cherry-pick or revert first. Unrelated untracked files are left alone. `--commit` cannot be combined with `--no-stage`.

The generated message uses the repository's conventional format and lists the affected files and folders, keeping trailing `/` characters for folders. For example:

```text
chore(git-sops): 🔐 Configure transparent file encryption

Protect the following paths:
- secrets/
- Web.config
```

Recipient-change messages also list the public age recipients added or removed and the protected paths re-encrypted. Private keys and file contents are never included in the generated message. Override the complete message with `--message`:

```powershell
git-sops protect config/ --commit --message "chore(config): 🔐 Encrypt application configuration"
```

`--message` requires `--commit` and cannot be empty. Commits use normal Git hooks, identity settings and signing configuration. If committing fails, the command reports failure and leaves the prepared changes staged for inspection and a normal `git commit` retry. Empty commits are skipped; adding an already configured recipient does not re-encrypt files or create another commit. An `unprotect` invocation that only warns and skips paths also creates no commit.

`join`, `decrypt`, `install-sops`, and `encrypt-history` do not accept these flags: they perform local setup, produce output, or rewrite existing commits.

## Creating an age identity

`git-sops init` and `git-sops join` create an identity automatically when none exists. It is written in the key location SOPS reads:

| OS | Key file |
| --- | --- |
| Windows | `%APPDATA%\sops\age\keys.txt` |
| Linux | `$XDG_CONFIG_HOME/sops/age/keys.txt` (default `~/.config/sops/age/keys.txt`) |
| macOS | `~/Library/Application Support/sops/age/keys.txt` |

`SOPS_AGE_KEY_FILE` overrides the location. The file is restricted to the current user (`0600` on Unix, a protected, owner-only DACL on Windows).

### Generate the private key manually

Optional; use the `age-keygen` tool from [age](https://github.com/FiloSottile/age) if you prefer to manage the key yourself:

```text
age-keygen -o <key file from the table above>
```

Restrict access to your account when creating a key manually. The git-sops generator applies those permissions before writing the identity.

### Obtain the public recipient

```text
age-keygen -y <key file>
```

`git-sops check` also prints the recipient of the local identity.

Example:

```text
age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Only the public `age1...` recipient goes into the repository.

## Using `--no-stage`

`--no-stage` leaves staging under your control. When introducing SOPS protection to files that are **already tracked as plaintext**, stage the configuration **and the protected files before committing**:

```text
git add .gitattributes .sops.yaml secrets appsettings.json

git hook run pre-commit

git commit -m "Protect secrets with SOPS"
```

Do not commit a new `.gitattributes` rule that marks an already-tracked plaintext file as `filter=sops` while leaving that file's plaintext blob in the index. The validator intentionally treats that as unsafe and rejects the commit.

If you require separate infrastructure and secret-history commits, introduce the infrastructure before activating the protection rules, rather than bypassing validation.

## Fresh clone / new machine

A fresh clone does **not** inherit local Git filter configuration.

That is intentional.

Before setup, protected files will normally appear in their encrypted repository form.

### Same user, new machine: reuse the private identity

Securely transfer the age private key file from the old trusted machine (see the key location table in [Creating an age identity](#creating-an-age-identity)). Do not transfer it through Git.

After cloning:

```text
git-sops join --age-key /secure/sops-age-keys.txt
```

The command:

- requires SOPS to be available;
- imports the private identity;
- configures the local filter;
- configures the pre-commit hook;
- decrypts encrypted working-tree copies;
- verifies that re-adding plaintext maps to exactly the same index ciphertext;
- runs the validator.

Final checks:

```text
git status --short
git hook list --show-scope pre-commit
```

`git status --short` should be empty.

### Same user, key already installed

If the age key file is already present:

```text
git-sops join
```

## Collaborator onboarding with an independent age key

Using a different age identity for each collaborator is preferable to sharing one private key.

### Step 1 — collaborator generates an identity

The collaborator clones the repository and runs:

```text
git-sops join
```

If no local age identity exists, the command generates one and prints the **public** recipient:

```text
age1...
```

At this stage the collaborator cannot decrypt existing files yet, and the command exits with code `2`.

They send only that public recipient to the maintainer. Never send or commit an `AGE-SECRET-KEY-...` value.

Alternatively, generate the identity manually with `age-keygen` and send the output of `age-keygen -y`, as described in [Creating an age identity](#creating-an-age-identity).

### Step 2 — maintainer adds the recipient

On a machine that already has access:

```text
git-sops add-recipient --name "Alex Morgan" age1...
```

The optional `--name` identifies one public key in the repository. Run `git-sops access` to see the names alongside the keys. To rename a collaborator, repeat the command with their current key and group. A name change alone leaves the encrypted files untouched. The interactive `git-sops add-recipient` prompt also accepts a name.

The tracked working tree must be clean, and `.sops.yaml` must have been generated by `git-sops` (or the earlier PowerShell script); a hand-written `.sops.yaml` is rejected.

The command:

- adds the public recipient to the managed `.sops.yaml`;
- freshly re-encrypts every tracked protected file for the updated recipient set;
- preserves the plaintext files in the maintainer's working tree;
- directly updates the Git index with the new ciphertext;
- confirms that normal clean-filter processing preserves that ciphertext;
- runs the pre-commit validator.

Review:

```powershell
git status
git diff --cached
git hook run pre-commit
```

Then commit and push:

```powershell
git commit -m "Grant SOPS access to collaborator"
git push
```

### Step 3 — collaborator pulls and joins again

```text
git pull

git-sops join
```

The existing collaborator private key can now decrypt the new SOPS metadata.

Verify as in the Quick start: `git status --short` should be empty and `git hook run pre-commit` should report `SOPS index validation passed.`

## Adding a new protected file later

Use `protect` to add files or directories to an initialized repository without replacing existing rules or recipients:

```powershell
git-sops protect src/Worker/service-secrets.txt
git-sops protect '**/*.env'
git-sops protect --protect "secrets/,appsettings.json"
git-sops protect --protect config/ --protect credentials.txt
git-sops verify
git diff --cached
git commit -m "Protect additional files"
```

Paths are relative to the repository root. Quote wildcard patterns so the shell passes them to git-sops as one rule. `'**/*.env'` covers `.env`, `app.env` and matching files in every subdirectory, including files added later. `'*.env'` covers only the repository root. New files ignored by Git stay untracked.

CSV parsing applies to `--protect`. Quote paths containing spaces. For a literal comma in a filename, use a positional argument. End directory paths with `/` when the directory does not currently exist. Already tracked plaintext is re-encrypted and staged, while working copies remain plaintext. These commands require a clean tracked working tree.

`init --protect` remains available for replacing the **complete** managed path set. It preserves existing recipients, but use `unprotect` when removing protection so the old encrypted index entry is converted to plaintext explicitly.

### Removing protection

Remove secrets from a file before publishing its plaintext, then commit that edit. To remove a complete configured rule:

```powershell
git-sops unprotect appsettings.json
git-sops unprotect --protect "secrets/,credentials.txt"
git-sops verify
git diff --cached
git commit -m "Publish files that no longer need encryption"
```

`unprotect` updates both configuration files and stages current contents as **plaintext**. It preserves recipients and all remaining rules. Earlier encrypted versions remain encrypted in history. Removing the last rule leaves an initialized repository with no protected paths; a later plain `init` preserves that empty set.

Only complete rules can be removed. If `secrets/` is protected, `unprotect secrets/token.txt` warns and skips the file, leaving it protected: individual exclusions are not supported. An explicitly configured child rule still covered by a remaining folder rule is also skipped with a warning. If every requested path is skipped, the command succeeds without changing configuration, the index or working files, even when changes are already staged. Other valid complete rules in the same invocation are processed normally. Independently configured child rules remain protected when their parent rule is removed. Files still covered by unmanaged attributes cause the operation to fail and restore the previous policy, index and touched files.

This is useful for public defaults, example files, or configuration that now references an external secret store. It is not a way to revoke access to previously disclosed secrets.

## Git worktrees

The design avoids storing repository encryption state in a fixed `.git/git-crypt`-style directory.

The local Git configuration is shared appropriately by linked worktrees, while each worktree has its own index.

Test:

```text
git worktree add ../repo-feature -b feature/example

cd ../repo-feature

cat secrets/secrets.txt
git status --short
```

The protected working-tree file should be plaintext and the status clean.

Check the committed blob:

```powershell
git show HEAD:secrets/secrets.txt
```

It should be encrypted.

## Decrypt without Git

`git-sops decrypt` needs only `sops` and an age key, not Git or the repository filter. It suits CI and deploy scripts.

```text
# one file to stdout
git-sops decrypt secrets/db.json

# every encrypted file under a directory, overwritten with plaintext
git-sops decrypt --in-place --recursive secrets/
```

When walking a directory, files that are not SOPS ciphertext are left alone. Only decrypt in place in a throwaway checkout: the files become plaintext on disk.

## Recovery and troubleshooting

### `error loading config: no matching creation rules found`

The filename supplied through `--filename-override` did not match a `.sops.yaml` `path_regex`.

Check both:

```text
cat .sops.yaml
git check-attr -a -- path/to/file
```

The generated `path_regex` accepts both `/` and `\` as separators (`[\\/]`); keep that if you edit it by hand.

### Working tree contains ciphertext after clone

The repository has not been bootstrapped locally yet.

Run:

```text
git-sops join
```

with a usable local age identity.

### `git status` shows a protected file modified immediately after bootstrap

Check whether a normal clean-filter pass produces the same blob:

```text
before=$(git rev-parse ':path/to/file')
git add -- path/to/file
after=$(git rev-parse ':path/to/file')
[ "$before" = "$after" ] && echo same
```

Expected: `same`.

`git-sops join` already performs this check automatically.

### Repeated `git add` changes the blob hash

That indicates the stable-ciphertext logic is not functioning. Run the check from the previous entry; for unchanged plaintext it must print `same`.

### SOPS cannot find the age key

Run:

```text
git-sops check
```

It prints the key file in use and the recipient derived from it. The recipient should be listed in the encrypted file's SOPS metadata.

### Filter executable is missing

Git runs `git-sops` through the filter config. Verify that it resolves and that SOPS is available:

```text
git-sops check
```

`init` and `join` store the quoted absolute path of the running `git-sops` executable in the filter, diff, merge and hook commands. This also works when a GUI Git client's `PATH` differs from your terminal's. Keep the executable in a stable location; if you move it, rerun `join` using its new path.

Older setups may refer to the bare `git-sops` command. A GUI client's reset, checkout or commit can then fail with `git-sops: command not found` even if the command works in your terminal. Rebuild or install the updated executable, then run it by its full path against the affected repository:

```powershell
& 'C:\path\to\git-sops.exe' -C 'C:\path\to\affected-repo' join
git -C 'C:\path\to\affected-repo' config --local --get filter.sops.clean
```

The configured command should start with the quoted absolute executable path, rather than bare `git-sops`. `join` repairs these local commands without rewriting history.
