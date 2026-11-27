# Security

git-sops uses Git filters to call the SOPS executable. SOPS encrypts the content and wraps the file’s data key for its recipients. git-sops manages path selection, recipient configuration, local Git settings and index checks. Treat the Git and SOPS executables, their update channels, your local machine and the repository policy as trusted inputs.

## What Git stores

- Filenames, directory layout, commit metadata, public age recipients and policy changes are visible to anyone who can read the repository.
- In structured files, field names are visible. SOPS also supports deliberate plaintext fields, including its default `_unencrypted` suffix. Keep sensitive data out of field names and fields excluded from encryption. Opaque file types use SOPS’s binary envelope.
- Your working files, editor backups, diffs and command output can contain plaintext. A merge uses private temporary files during normal execution. Protect the checkout, temp directory and logs accordingly.
- Removing a recipient changes access to newly encrypted versions. A former recipient can still decrypt older commits and retain previous plaintext or data keys. Rotate exposed credentials at their source.

## What verification checks

`git-sops verify` reads the Git index and checks staged filter attributes and SOPS file metadata. For a managed policy it also checks filter coverage. For a grouped policy it compares the age recipients recorded in each protected blob with the staged rule. These checks run without a private key. SOPS verifies the file’s integrity on decryption.

A contributor who can change both policy files can change what is protected and who receives the keys. Review changes to `.gitattributes`, `.sops.yaml` and the CI workflow. Run the validator from a trusted installation in CI and use a required merge check if you need enforcement. The check covers the current index. Earlier commits, untracked files and secrets outside selected paths need separate review.

## Dependencies and local keys

The default installer verifies the upstream checksum manifest against a SHA-256 pinned in git-sops, then checks the executable against that manifest. For an explicitly selected version it requires a SHA-256 from the release API or its checksum manifest. A checksum identifies a particular build. Assess the advisories for the SOPS build you deploy as well as those for git-sops. You can supply an independently maintained SOPS binary on `PATH`. [SOPS security advisories](https://github.com/getsops/sops/security/advisories)

On 2026-11-27, `govulncheck` v1.10.0 reported advisories for symbols present in two official SOPS v3.13.3 executables. Both downloads matched the upstream SHA-256. [Upstream release](https://github.com/getsops/sops/releases/tag/v3.13.3)

| Executable | Advisories | SHA-256 |
| --- | ---: | --- |
| Windows/amd64 | 36 | `a4a9a398858fe8b2ef72d9686d930bf7c5cece9be74ad83ac3b53cfdd70e6b1c` |
| Linux/amd64 | 35 | `e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b` |

Binary scanning identifies included code. Reachability through the Git filters requires separate assessment. To check your deployment, run `govulncheck -mode=binary <path-to-sops>` against the executable selected by `git-sops check`. [Go vulnerability scanning](https://go.dev/doc/security/vuln/)

Keep the age private identity outside the repository. When git-sops creates or imports a key, it restricts the key file to the current account before writing key material. Back up the identity securely and keep a recovery recipient where appropriate.

## Reporting an issue

Use GitHub’s **Security → Report a vulnerability** option when available. If it is unavailable, open a public issue asking for a private contact. Keep the technical details private until you and the maintainer have agreed on disclosure. A report can use a temporary repository, generated test keys, the affected git-sops version, operating system, Git version and SOPS version. Keep real keys and production data out of the report.
