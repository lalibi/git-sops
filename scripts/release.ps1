#requires -Version 7.4
#requires -Modules @{ ModuleName = 'PwshSpectreConsole'; ModuleVersion = '2.0.0' }

[CmdletBinding(DefaultParameterSetName = 'Release')]
param(
    [Parameter(ParameterSetName = 'Release')][switch]$Publish,
    [Parameter(Mandatory, ParameterSetName = 'Watch')]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')][string]$WatchTag
)

$ErrorActionPreference = 'Stop'

function Invoke-Git {
    & git @args
    if ($LASTEXITCODE -ne 0) {
        throw "git $($args[0]) failed (exit $LASTEXITCODE)."
    }
}

function Get-ReleaseRepository {
    if (!(Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'Install the GitHub CLI (gh) to monitor releases.'
    }
    $remote = Invoke-Git remote get-url --push origin
    # Accept both URL and SCP-style Git remotes. Pass only host/owner/repo to gh.
    if ($remote -notmatch '^(?:(?:https?|ssh|git)://)?(?:[^/@]+@)?(?<server>[^/:]+)(?::\d+/|[:/])(?<owner>[^/]+)/(?<project>[^/]+)/?$') {
        throw 'Could not identify a GitHub repository from the origin push URL.'
    }
    return '{0}/{1}/{2}' -f $Matches.server, $Matches.owner, ($Matches.project -replace '\.git$', '')
}

function Format-ReleaseState($Item) {
    $state = $Item.conclusion ? $Item.conclusion : $Item.status
    switch ($state) {
        'success'     { '[green]✓ Passed[/]' }
        'failure'     { '[red]✗ Failed[/]' }
        'in_progress' { '[cyan]Running[/]' }
        'pending'     { '[grey]Pending[/]' }
        'queued'      { '[grey]Queued[/]' }
        'skipped'     { '[grey]Skipped[/]' }
        'cancelled'   { '[yellow]Cancelled[/]' }
        default       { Get-SpectreEscapedText ($state -replace '_', ' ') }
    }
}

function Format-ReleaseJobs($Snapshot) {
    $columns = @{ ubuntu = 'Linux'; windows = 'Windows'; macos = 'macOS' }
    $unreported = $Snapshot.status -eq 'completed' ? '—' : 'Waiting'
    $summary = [ordered]@{ Step = 'Job'; Linux = $unreported; Windows = $unreported; macOS = $unreported }
    $steps = @{}
    $title = @("Workflow: $(Format-ReleaseState $Snapshot)")
    foreach ($job in $Snapshot.jobs) {
        if ($job.name -notmatch '\((ubuntu|windows|macos)-latest\)$') {
            $title += "$(Get-SpectreEscapedText $job.name): $(Format-ReleaseState $job)"
            continue
        }
        $column = $columns[$Matches[1]]
        $summary[$column] = Format-ReleaseState $job
        foreach ($step in $job.steps) {
            $key = "$($step.number):$($step.name)"
            if (!$steps.ContainsKey($key)) {
                $label = $step.name -replace '@[0-9a-f]{40}\b', '' -replace '^(Post )?Run ', '$1'
                $steps[$key] = [pscustomobject]@{
                    Number = $step.number; Step = Get-SpectreEscapedText $label
                    Linux = '—'; Windows = '—'; macOS = '—'
                }
            }
            $steps[$key].$column = Format-ReleaseState $step
        }
    }
    $rows = @([pscustomobject]$summary) + @($steps.Values | Sort-Object Number, Step)
    $table = $rows | Format-SpectreTable -Property Step,Linux,Windows,macOS -Title ($title -join '   ') -AllowMarkup -Border Rounded -Color Grey -HeaderColor Cyan
    foreach ($column in $table.Columns) {
        $column.Header.Justification = 'Center'
    }
    foreach ($i in 1..3) {
        foreach ($row in $table.Rows) {
            $row[$i].Justification = 'Right'
        }
    }
    return $table
}

function Watch-ReleaseJobs($Repo, $Run, $Tag) {
    $poll = {
        param($Context)
        $previous = ''
        do {
            $json = (gh run view $Run.databaseId --repo $Repo --json status,conclusion,jobs) -join "`n"
            if ($LASTEXITCODE -ne 0) { throw "Could not read workflow jobs for $Tag. See $($Run.url)" }
            $snapshot = $json | ConvertFrom-Json
            if ($json -cne $previous) {
                $table = Format-ReleaseJobs $snapshot
                if ($Context) {
                    $Context.UpdateTarget($table)
                    $Context.Refresh()
                } else {
                    Write-Host
                    $table | Out-SpectreHost
                }
                $previous = $json
            }
            if ($snapshot.status -eq 'completed') { break }
            Start-Sleep -Seconds 15
        } while ($true)
        if ($snapshot.conclusion -ne 'success') {
            throw "Release workflow for $Tag finished with conclusion '$($snapshot.conclusion)'. See $($Run.url)"
        }
    }
    if ([Console]::IsOutputRedirected -or !$Host.UI.SupportsVirtualTerminal) {
        & $poll
    } else {
        Write-Host
        Invoke-SpectreLive -Data ([Spectre.Console.Markup]::new('Loading workflow jobs…')) -ScriptBlock $poll
    }
}

function Wait-Release($Repo, $Tag, $Commit) {
    $filters = @('--workflow', 'release.yml', '--event', 'push', '--branch', $Tag)
    if ($Commit) { $filters += '--commit', $Commit }
    Write-Host
    Write-SpectreHost "[grey]Waiting for the release workflow for $Tag...[/]"
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        $json = gh run list --repo $Repo @filters --limit 1 --json databaseId,url
        if ($LASTEXITCODE -ne 0) { throw "Could not look up the release workflow for $Tag. Check gh authentication and repository access." }
        $run = $json | ConvertFrom-Json | Select-Object -First 1
        if ($run) { break }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    if (!$run) { throw "No release workflow appeared for $Tag. Retry with -WatchTag $Tag." }

    Write-Host "Release workflow: $($run.url)"
    Watch-ReleaseJobs $Repo $run $Tag

    $expected = @('checksums.txt')
    foreach ($os in 'windows', 'darwin', 'linux') {
        $extension = if ($os -eq 'windows') { 'zip' } else { 'tar.gz' }
        foreach ($arch in 'amd64', 'arm64') {
            $expected += "git-sops_$($Tag.Substring(1))_${os}_$arch.$extension"
        }
    }
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        $result = gh release view $Tag --repo $Repo --json tagName,isDraft,url,assets 2>&1
        if ($LASTEXITCODE -eq 0) {
            $release = $result | ConvertFrom-Json
            $uploaded = @($release.assets | Where-Object { $_.state -eq 'uploaded' -and $_.size -gt 0 } | ForEach-Object name)
            $missing = @($expected | Where-Object { $_ -cnotin $uploaded })
            if ($release.tagName -ceq $Tag -and !$release.isDraft -and !$missing.Count) {
                Write-Host
                Write-Host "Release available: $($release.url)"
                return
            }
            $reason = if ($release.isDraft) { 'still a draft' } else { "missing uploads: $($missing -join ', ')" }
        } else {
            $reason = $result -join ' '
        }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Workflow succeeded, but release $Tag could not be verified ($reason). Retry with -WatchTag $Tag."
}

if ($WatchTag) {
    Wait-Release (Get-ReleaseRepository) $WatchTag
    return
}

$commit = Invoke-Git rev-parse --verify HEAD
if ((Invoke-Git rev-parse --is-shallow-repository) -eq 'true') {
    throw 'Release calculation needs the full history. Run git fetch --unshallow --no-tags first.'
}

$tagRoot = 'refs/tags'
if ($Publish) {
    if ((Invoke-Git branch --show-current) -ne 'main') {
        throw 'Switch to main before publishing.'
    }
    # Mirror published tags separately so an older local tag can keep its own object.
    $tagRoot = 'refs/git-sops-release/origin/tags'
    Invoke-Git fetch --atomic --no-tags --prune --no-prune-tags origin main "+refs/tags/v*:${tagRoot}/v*"
}

$stableTag = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
$previous = Invoke-Git for-each-ref "--merged=$commit" --sort=-version:refname '--format=%(refname)' "$tagRoot/v*" |
    Where-Object { $_.Substring($tagRoot.Length + 1) -cmatch $stableTag } |
    Select-Object -First 1

$range = $commit
$base = '0.0.0'
if ($previous) {
    $range = "$previous..$commit"
    $base = $previous.Substring("$tagRoot/v".Length)
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
Write-Host
Write-SpectreRule -Title $title -Color Cyan
if ($rows.Count) {
    $table = $rows | Format-SpectreTable -Border Rounded -Color Grey -HeaderColor Cyan
    foreach ($column in $table.Columns) {
        $column.Header.Justification = 'Center'
    }
    $table | Out-SpectreHost
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

$repo = Get-ReleaseRepository
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
Write-SpectreHost "[green]Pushed main and $tag to origin.[/]"
Wait-Release $repo $tag $commit
