param(
    [string]$Distribution = 'Ubuntu-24.04',
    [string]$LogDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work\tmp\wsl-cache-cleanup')
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
if (-not [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run virtual disk compaction from an elevated PowerShell.'
}
$registered = @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' |
    ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } |
    Where-Object { $_.DistributionName -ceq $Distribution })
if ($registered.Count -ne 1 -or $registered[0].Version -ne 2) {
    throw 'Select exactly one registered WSL 2 build distribution.'
}
$base = [IO.Path]::GetFullPath($registered[0].BasePath).TrimEnd('\')
$name = $registered[0].VhdFileName
if (-not $name) { $name = 'ext4.vhdx' }
if ([IO.Path]::GetFileName($name) -ne $name -or [IO.Path]::GetExtension($name) -ne '.vhdx') {
    throw 'Unexpected virtual disk filename.'
}
$disk = [IO.Path]::GetFullPath((Join-Path $base $name))
if ([IO.Path]::GetDirectoryName($disk) -ne $base -or $disk.Contains('"')) {
    throw 'Virtual disk path is outside the registered distribution.'
}
$before = (Get-Item -LiteralPath $disk).Length
$task = [IO.Path]::GetFullPath($LogDirectory)
New-Item -ItemType Directory -Path $task -Force | Out-Null

# Stop only the build distribution, and refuse to interrupt active workloads.
$preflight = @'
set -eu
if ps -eo comm= | grep -Eq '^(python|node|npm|uvicorn|spearmint|qemu|gcc|cc1|clang|make|ninja|rustc|cargo)'; then
    echo 'Active build or application process detected; leave this distribution running.' >&2
    exit 1
fi
sync
fstrim -v /
'@
& wsl.exe --distribution $Distribution --user root -- sh -c $preflight
if ($LASTEXITCODE -ne 0) { throw 'Build distribution preflight or trim failed.' }
& wsl.exe --terminate $Distribution
if ($LASTEXITCODE -ne 0) { throw 'Could not stop the selected build distribution.' }
$running = @(& wsl.exe --list --running --quiet) | ForEach-Object { $_.Replace("`0", '').Trim() }
if ($running -contains $Distribution) { throw 'Build distribution is still running.' }
# WSL can retain stopped distributions' disks while other distributions run.
# Defer physical compaction rather than stopping unrelated services.
$released = $false
try {
    $stream = [IO.File]::Open($disk, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $stream.Dispose()
    $released = $true
} catch [IO.IOException] {
    $released = $false
}
if (-not $released) {
    $pending = [pscustomobject]@{
        distribution = $Distribution
        disk = $disk
        status = 'deferred'
        reason = 'WSL still holds the disk; retry when unrelated WSL workloads have stopped.'
        before_bytes = $before
        after_bytes = (Get-Item -LiteralPath $disk).Length
        reclaimed_bytes = 0
        recorded_at = (Get-Date).ToString('o')
    }
    $pending | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $task 'compaction.json') -Encoding UTF8
    Write-Warning $pending.reason
    return $pending
}
$commands = Join-Path $task 'compact-diskpart.txt'
[IO.File]::WriteAllLines($commands, @("select vdisk file=`"$disk`"", 'compact vdisk', 'exit'),
    [Text.UTF8Encoding]::new($false))
$output = & diskpart.exe /s $commands | Tee-Object -FilePath (Join-Path $task 'compact-diskpart.log')
if ($LASTEXITCODE -ne 0) { throw 'DiskPart could not compact the build virtual disk.' }
if (($output -join "`n") -notmatch '(?i)successfully compacted|成功.*压缩|压缩.*成功') {
    throw 'DiskPart did not confirm successful virtual disk compaction; inspect compact-diskpart.log.'
}
$after = (Get-Item -LiteralPath $disk).Length
if ($after -gt $before) { throw 'Unexpected virtual disk growth during compaction.' }
$result = [pscustomobject]@{
    distribution = $Distribution
    disk = $disk
    status = 'completed'
    before_bytes = $before
    after_bytes = $after
    reclaimed_bytes = $before - $after
    completed_at = (Get-Date).ToString('o')
}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $task 'compaction.json') -Encoding UTF8
$result
