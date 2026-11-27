# Paths, recipients and file formats

## Choosing protected paths

Pass repository-relative files, directories or quoted filename patterns to `git-sops protect`. A directory rule covers its descendants, including files added later. In a filename, `*` matches zero or more characters. Put `**/` immediately before the filename to match at any depth under a fixed directory. For example, `git-sops protect 'services/**/*.env'` covers both `services/.env` and `services/api/prod.env`.

Git attributes select the filter and the SOPS creation rules select the age recipients. With recipient groups, exact file and directory rules take precedence over wildcard rules. Among matching patterns, the deepest fixed directory wins. Within that directory a filename pattern takes precedence over a recursive pattern, so `'*.env'` can assign a different group at the root than `'**/*.env'`. Further ties favor more literal filename characters, then policy order.

Keep the generated configuration and working files that git-sops updates in regular files under the checkout. Setup rejects symlinks and directory junctions when writing these files.

## `.gitattributes`: deciding what Git encrypts

Git's `filter` attribute activates a named clean/smudge filter for a path.

A protected directory:

```gitattributes
/secrets/** filter=sops diff=sops merge=sops -text
```

A protected file in the repository root:

```gitattributes
/appsettings.json filter=sops diff=sops merge=sops -text
```

A protected file inside a directory that also contains normal unencrypted files:

```gitattributes
/src/Web/appsettings.Production.json filter=sops diff=sops merge=sops -text
```

These rules do **not** encrypt sibling files.

For example:

```text
src/Web/
├── appsettings.Production.json    encrypted
├── Program.cs                     normal
├── Web.csproj                     normal
└── README.md                      normal
```

with:

```gitattributes
/src/Web/appsettings.Production.json filter=sops diff=sops merge=sops -text
```

Only the single JSON file is filtered.

### Protecting every appsettings file

If that is genuinely desired:

```gitattributes
**/appsettings.json filter=sops diff=sops merge=sops -text
**/appsettings.*.json filter=sops diff=sops merge=sops -text
```

Be careful: broad patterns may encrypt files that were intended to remain public.

### Why `-text`

`-text` disables Git EOL normalization for protected paths. The filter owns the exact transformation between working-tree bytes and repository bytes.

### Diff and merge drivers

`diff=sops` and `merge=sops` make `git diff`, `git log -p`, `git show` and `git merge` work on the decrypted content instead of ciphertext.

- **diff**: `diff.sops.textconv` runs `git-sops textconv`, which decrypts each side. If a blob cannot be decrypted (for example the key is missing) the ciphertext is shown instead. `diff.sops.cachetextconv` is set to false in the local Git config, because Git would store the decrypted text in the repository.
- **merge**: `merge.sops.driver` runs `git-sops merge`, which decrypts base, ours and theirs, merges the plaintext with `git merge-file`, and encrypts the result. A clean merge produces new ciphertext that is staged for you. On a conflict the working-tree file holds plaintext conflict markers; resolve them and run `git add`, which encrypts the resolved file. Unresolved markers are encrypted like any other content, so resolve them before committing.

Both drivers are configured by `git-sops init` and `git-sops join`. Existing repositories pick up the attributes by running `git-sops init` again. A temporary plaintext copy of the three versions exists in your temp directory while a merge runs and is removed afterwards.

## `.sops.yaml`: deciding which age recipients can encrypt/decrypt

`.gitattributes` tells Git **which files use the filter**.

`.sops.yaml` tells SOPS **which encryption keys apply to those paths**.

Both must agree.

git-sops writes one creation rule per protected path. Each rule references the same list of public age recipients:

```yaml
# Managed by git-sops

recipients: &recipients
  - age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

creation_rules:
# protected-path: secrets/
  - path_regex: '^secrets[\\/].*$'
    age: *recipients

# protected-path: appsettings.json
  - path_regex: '^appsettings\.json$'
    age: *recipients

# protected-path: src/Web/appsettings.Production.json
  - path_regex: '^src[\\/]Web[\\/]appsettings\.Production\.json$'
    age: *recipients
```

The separator expression `[\\/]` allows both `/` and `\`. Existing managed policies with a combined regex still work. Upgrading the binary, running `join`, `check`, or `verify`, and ordinary Git operations leave the policy as written. The next policy edit, such as adding a path with `git-sops protect`, writes one rule per path and retains the shared recipients. v0.3.2 can read and edit that layout. Its next policy edit writes the combined regex again.

## Named recipient groups

Use groups when people need different decryption access. A repository with one shared recipient list keeps the v0.3.2-compatible format even when you explicitly select `--group default`. Creating the first non-default group switches the policy format and carries the existing recipients into `default`. Upgrade collaborators and CI before committing that change. Supply each person's public age key in place of the placeholders below. Include your own public key in each group you need to decrypt.

```sh
git-sops group set certificates YOUR_AGE_KEY ALICE_AGE_KEY --commit
git-sops protect certs/ --group certificates --dry-run
git-sops protect certs/ --group certificates --commit

git-sops group set database YOUR_AGE_KEY BOB_AGE_KEY --commit
git-sops protect ravendb/ --group database --commit
git-sops access
git-sops access BOB_AGE_KEY
```

Each assignment names the complete group for that path. Unassigned paths use `default`. Within a directory, the most specific rule wins. For example, `git-sops protect secrets/production.env --group certificates` restricts that file while the rest of `secrets/` keeps its existing group. Use `--group default` to return a rule to the default list.

For example, these generated rules give the certificates group access to one file inside a directory shared with the default group:

```yaml
recipient_groups:
  certificates: &certificates
    - age1... # Alice
    - age1... # recovery
  default: &default
    - age1... # Bob
    - age1... # recovery

creation_rules:
# protected-path: secrets/production.env
  - path_regex: '^secrets[\\/]production\.env$'
    age: *certificates

# protected-path: secrets/
  - path_regex: '^secrets[\\/].*$'
    age: *default
```

`git-sops access` lists each public age key once, its groups, and how many protected files in the Git index are encrypted for it. This includes unchanged tracked files. A zero count means the key is configured but appears in no indexed file. An `(index only)` entry identifies a key present in ciphertext without a group in the working policy. Shared policies show one group named `default`. With a custom policy, the command reports the recipients recorded in age-only ciphertext for tracked files marked `filter=sops`.

`git-sops access BOB_AGE_KEY` lists that key's rules and individual files. Both forms read public metadata and work without a private key. An age public key identifies a recipient key. Mapping it to a person requires knowing who holds the private key.

To preview a change, add `--dry-run`. Applying it stages the policy and re-encrypts tracked files whose effective recipients change. The operator needs a key that can decrypt each affected file under the old policy. Commit each prepared change before starting another.

```sh
git-sops add-recipient RECOVERY_AGE_KEY --group database --commit
git-sops remove-recipient BOB_AGE_KEY --everywhere --dry-run
git-sops remove-recipient BOB_AGE_KEY --everywhere --commit
```

`group set` replaces the entire named list. `add-recipient` and `remove-recipient` edit the default list unless given `--group`. `--everywhere` removes a recipient from all lists together. Each active group and the default must retain a recipient. `check` flags single-recipient groups so you can add a second maintainer or offline recovery key. A former recipient can still read old commits and copies they already decrypted.

Group policies use the header `# Managed by git-sops (recipient groups v1)`. v0.3.2 treats that file as custom and refuses `protect`, `add-recipient`, and `remove-recipient`. Forcing an old `init` to replace the file can discard the group assignments. After upgrading, run `git-sops join` to configure the clone. Authorized files decrypt normally. Files for other groups stay encrypted through checkout and `git add -A`. The pre-commit check compares the staged files' age recipients with the staged group policy. Git hosting permissions still control who can push changes.

## File formats

The filter chooses a SOPS format from the original filename.

| Extension       | Plaintext input | Repository representation |
| --------------- | --------------- | ------------------------- |
| `.json`         | JSON            | SOPS JSON                 |
| `.yaml`, `.yml` | YAML            | SOPS YAML                 |
| `.env`          | dotenv          | SOPS dotenv               |
| `.ini`          | INI             | SOPS INI                  |
| anything else   | binary          | SOPS JSON binary envelope |

### JSON / appsettings.json

For JSON, SOPS preserves the JSON tree and encrypts leaf values.

Example local working tree:

```json
{
  "ConnectionStrings": {
    "Default": "Server=...;Password=secret"
  },
  "ApiKey": "secret"
}
```

The committed representation contains values similar to:

```json
{
  "ConnectionStrings": {
    "Default": "ENC[AES256_GCM,...]"
  },
  "ApiKey": "ENC[AES256_GCM,...]",
  "sops": {
    ...
  }
}
```


### JSON limitations

A top-level JSON array cannot carry the normal SOPS metadata structure. If a JSON file has a top-level array or otherwise cannot be handled as structured SOPS JSON, use an extension that selects binary mode if your application permits renaming the file.

### Arbitrary text and binary files

A file such as:

```text
secrets/secrets.txt
```

that is not JSON/YAML/ENV/INI is treated as **binary**.

The working tree remains the original plaintext text/binary bytes.

The Git blob becomes a SOPS JSON envelope such as:

```json
{
  "data": "ENC[AES256_GCM,...]",
  "sops": {
    ...
  }
}
```

The filename can remain `.txt`; the filter explicitly tells SOPS that plaintext input is binary and encrypted input is JSON.

This also works for many other opaque files, for example `.pem`, `.key`, `.pfx`, `.bin`, provided the application can safely use the decrypted local file.
