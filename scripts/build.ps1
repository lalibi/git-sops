[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

go build -C $repoRoot -o ./bin/ ./cmd/git-sops
if ($LASTEXITCODE -ne 0) {
    throw "go build failed (exit $LASTEXITCODE)."
}

Write-Host "Built git-sops in $(Join-Path $repoRoot 'bin')."
