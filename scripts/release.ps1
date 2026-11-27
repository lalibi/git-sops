#requires -Version 7.4
#requires -Modules @{ ModuleName = 'PwshSpectreConsole'; ModuleVersion = '2.0.0' }

[CmdletBinding()]
param([switch]$Publish)

$ErrorActionPreference = 'Stop'

function Invoke-Git {
    & git @args
    if ($LASTEXITCODE -ne 0) {
        throw "git $($args[0]) failed (exit $LASTEXITCODE)."
    }
}

$commit = Invoke-Git rev-parse --verify HEAD
if ((Invoke-Git rev-parse --is-shallow-repository) -eq 'true') {
    throw 'Release calculation needs the full history. Run git fetch --unshallow --tags first.'
}

if ($Publish) {
    if ((Invoke-Git branch --show-current) -ne 'main') {
        throw 'Switch to main before publishing.'
    }
    Invoke-Git fetch --tags origin main
    $publishedTags = @{}
    foreach ($ref in (Invoke-Git ls-remote --refs --tags origin 'refs/tags/v*')) {
        $publishedTags[$ref.Split([char]9)[1].Substring('refs/tags/'.Length)] = $true
    }
}

$stableTag = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
$previous = Invoke-Git tag --merged $commit --sort=-version:refname --list 'v*' |
    Where-Object { $_ -cmatch $stableTag -and (!$Publish -or $publishedTags.ContainsKey($_)) } |
    Select-Object -First 1

$range = $commit
$base = '0.0.0'
if ($previous) {
    $range = "$previous..$commit"
    $base = $previous.Substring(1)
}

# NUL separates subjects and bodies even when commit messages span several lines.
$log = (Invoke-Git log --no-show-signature -z '--format=%h%x00%s%x00%b' $range) -join "`n"
$fields = $log -split '\x00'
$rows = @(for ($i = 0; $i + 2 -lt $fields.Count; $i += 3) {
    $subject = $fields[$i + 1]
    $body = $fields[$i + 2]
    if ($subject -match '^[\w-]+(?:\([^()]+\))?!: ' -or $body -cmatch '(?m)^BREAKING[ -]CHANGE: ') {
        $impact = 'major'
    } elseif ($subject -match '^feat(?:\([^()]+\))?: ') {
        $impact = 'minor'
    } elseif ($subject -match '^(fix|perf)(?:\([^()]+\))?: ') {
        $impact = 'patch'
    } else {
        $impact = 'none'
    }
    [pscustomobject]@{ Commit = $fields[$i]; Impact = $impact; Subject = $subject }
})

$title = if ($Publish) { 'Publish release' } else { 'Release preview' }
Write-SpectreRule -Title $title -Color Cyan
if ($rows.Count) {
    $rows | Format-SpectreTable -Border Rounded -Color Grey -HeaderColor Cyan | Out-SpectreHost
}

$bump = 'major', 'minor', 'patch' | Where-Object { $_ -in $rows.Impact } | Select-Object -First 1
if (!$bump) {
    Write-SpectreHost '[grey]No release needed. No unreleased commit requests a version bump.[/]'
    return
}

$major, $minor, $patch = $base.Split('.') | ForEach-Object { [bigint]$_ }
switch ($bump) {
    'major' { $major += 1; $minor = 0; $patch = 0 }
    'minor' { $minor += 1; $patch = 0 }
    'patch' { $patch += 1 }
}
$tag = "v$major.$minor.$patch"
Write-SpectreHost "[grey]v$base ->[/] [bold green]$tag[/] ($bump) at $($commit.Substring(0, 7))"
if (!$Publish) { return }

# Publish the exact commit inspected above. A rejected push updates neither remote ref.
Invoke-Git tag -a $tag $commit -m "Release $tag"
$tagRef = "refs/tags/$tag"
$tagObject = Invoke-Git rev-parse $tagRef
try {
    Invoke-Git push --atomic --no-follow-tags origin "${commit}:refs/heads/main" "${tagRef}:$tagRef"
} catch {
    Invoke-Git update-ref -d $tagRef $tagObject
    throw
}
Write-SpectreHost "[green]Pushed main and $tag to origin.[/] The release workflow will publish the archives."
