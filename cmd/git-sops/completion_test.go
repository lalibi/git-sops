package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPowerShellProfileCompletion(t *testing.T) {
	repo := t.TempDir()
	if out, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %s: %v", out, err)
	}
	const key = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	write(t, filepath.Join(repo, ".sops.yaml"), "# Managed by git-sops\n# protected-path: secrets/\n# recipient-name: "+key+" Alex\nrecipients: &recipients\n  - "+key+"\n")
	t.Setenv("GIT_SOPS_TEST_EXE", binary)
	t.Setenv("GIT_SOPS_TEST_REPO", repo)
	t.Setenv("GIT_SOPS_TEST_KEY", key)
	for _, shell := range []string{"pwsh", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			exe, err := exec.LookPath(shell)
			if err != nil {
				t.Skip("shell unavailable")
			}
			const script = `
$ErrorActionPreference = 'Stop'
$profileFile = Join-Path (Get-Location).Path 'profile dir/test profile.ps1'
$preview = (& $env:GIT_SOPS_TEST_EXE completion powershell --show) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $profileFile)) { throw 'Preview failed' }
& $env:GIT_SOPS_TEST_EXE completion powershell --install $profileFile
if ($LASTEXITCODE -ne 0) { throw 'Profile installation failed' }
$installed = [IO.File]::ReadAllText($profileFile)
if ($installed.TrimEnd() -cne $preview) { throw 'Installed block differs from preview' }
$repeat = & $env:GIT_SOPS_TEST_EXE completion powershell --install $profileFile
if ($LASTEXITCODE -ne 0 -or $repeat -notmatch 'already installed' -or [IO.File]::ReadAllText($profileFile) -cne $installed) { throw 'Repeated installation changed the profile' }
. $profileFile
if ((Get-Alias gs).Definition -cne $env:GIT_SOPS_TEST_EXE) { throw 'Incorrect executable in gs alias' }
function Assert-Completion($line, $want) {
    $matches = (TabExpansion2 $line $line.Length).CompletionMatches
    if ($want -notin @($matches | ForEach-Object { $_.CompletionText.TrimEnd() })) {
        throw "Missing '$want' for '$line'. Got $($matches.CompletionText). Errors: $Error"
    }
}
Assert-Completion 'gs sta' 'status'
Assert-Completion 'gs group s' 'set'
$env:PATH = (Split-Path $env:GIT_SOPS_TEST_EXE) + [IO.Path]::PathSeparator + $env:PATH
Assert-Completion 'git-sops status --unpro' '--unprotected'
Set-Location -LiteralPath $env:GIT_SOPS_TEST_REPO
Assert-Completion 'gs protect --group def' 'default'
Assert-Completion 'gs unprotect sec' 'secrets/'
Assert-Completion 'gs access age1' $env:GIT_SOPS_TEST_KEY
`
			cmd := exec.Command(exe, "-NoProfile", "-NonInteractive", "-Command", script)
			cmd.Dir = t.TempDir()
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("PowerShell completion: %s: %v", out, err)
			}
		})
	}
}
