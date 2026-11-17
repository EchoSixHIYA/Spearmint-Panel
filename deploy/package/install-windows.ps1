[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string]$Origin,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,
    [string]$Bind = '127.0.0.1',
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA 'Programs\Spearmint'),
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'spearmint'),
    [ValidatePattern('^[^\\/:*?"<>|\[\]\x00-\x1f]{1,120}$')]
    [string]$TaskName = 'Spearmint',
    [ValidateSet('Interactive', 'S4U')]
    [string]$TaskLogonType = 'Interactive',
    [string]$Certificate,
    [string]$PrivateKey,
    [ValidateNotNullOrEmpty()]
    [string]$GroveCA,
    [switch]$StageOnly,
    [switch]$Upgrade,
    [switch]$OpenSetup,
    [ValidateNotNullOrEmpty()]
    [string]$JoinGrove,
    [string]$VerifyBackup,
    [ValidatePattern('\A[a-f0-9]{64}\z', Options = [Text.RegularExpressions.RegexOptions]::None)]
    [string]$ExpectedBackupSha256,
    [ValidatePattern('\A[a-f0-9]{64}\z', Options = [Text.RegularExpressions.RegexOptions]::None)]
    [string]$ExpectedPackageSha256,
    [switch]$CheckUpgrade,
    [switch]$RecoverUpgrade,
    [Parameter(ParameterSetName = 'Install')]
    [switch]$KeepStopped,
    [ValidateNotNullOrEmpty()]
    [string]$WebDirectory,
    [ValidatePattern('\Aspm1-[a-f0-9]{64}\z', Options = [Text.RegularExpressions.RegexOptions]::None)]
    [string]$ExpectedNode,
    [ValidatePattern('\A[a-f0-9]{40}\z', Options = [Text.RegularExpressions.RegexOptions]::None)]
    [string]$ExpectedCommit,
    [ValidatePattern('\A[a-f0-9]{40}\z', Options = [Text.RegularExpressions.RegexOptions]::None)]
    [string]$ExpectedCurrentCommit,
    [Parameter(Mandatory = $true, ParameterSetName = 'RecoveryStatus')]
    [switch]$UpgradeRecoveryStatus
)
$ErrorActionPreference = 'Stop'

$upgradeMode = $Upgrade -or $CheckUpgrade
if ($OpenSetup -and ($StageOnly -or $upgradeMode -or $RecoverUpgrade)) {
    throw '-OpenSetup requires a normal installation.'
}
if ($JoinGrove -and ($StageOnly -or $upgradeMode -or $RecoverUpgrade)) {
    throw '-JoinGrove requires a normal installation.'
}

function Get-FullFileSystemPath([string]$Value) {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Value)
    if (-not [IO.Path]::IsPathRooted($path)) {
        throw 'Use a Windows filesystem path.'
    }
    [IO.Path]::GetFullPath($path)
}

function Test-WithinPath([string]$Path, [string]$Parent) {
    $prefix = $Parent.TrimEnd('\', '/') + '\'
    $Path.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-LocalTaskPath([string]$Path) {
    $root = [IO.Path]::GetPathRoot($Path)
    if ($root -notmatch '^[a-zA-Z]:\\$' -or [IO.DriveInfo]::new($root).DriveType -ne [IO.DriveType]::Fixed) {
        throw 'S4U tasks require installation, state, Web and TLS files on local fixed disks.'
    }
}

function New-PanelTaskTrigger([Security.Principal.WindowsIdentity]$Identity) {
    if ($TaskLogonType -eq 'S4U') {
        New-ScheduledTaskTrigger -AtStartup
    } else {
        New-ScheduledTaskTrigger -AtLogOn -User $Identity.Name
    }
}

function Quote-TaskValue([string]$Value) {
    if ($Value.Contains('"')) {
        throw 'Task paths and the origin must not contain double quotes.'
    }
    # Preserve trailing path separators when Windows parses the closing quote.
    '"' + ($Value -replace '(\\+)$', '$1$1') + '"'
}

function Test-TaskOwner([string]$UserId, [Security.Principal.WindowsIdentity]$Identity) {
    if (-not $UserId) {
        return $false
    }
    if ($UserId -eq $Identity.User.Value) {
        return $true
    }
    try {
        $account = [Security.Principal.NTAccount]::new($UserId)
        $account.Translate([Security.Principal.SecurityIdentifier]).Value -eq $Identity.User.Value
    } catch [Security.Principal.IdentityNotMappedException] {
        $false
    }
}

function Copy-PackageFiles([string]$Source, [string]$Destination, [string]$ChecksumFile) {
    $files = Get-Content -LiteralPath $ChecksumFile -Raw | ConvertFrom-Json
    foreach ($required in @('spearmint.exe', 'web/index.html', 'build-manifest.json')) {
        if (-not $files.PSObject.Properties[$required]) {
            throw "Missing package checksum: $required"
        }
    }
    foreach ($entry in $files.PSObject.Properties) {
        $relative = $entry.Name
        if ($relative -match '^[ /]|//|[. /]$|[. ]/|[<>:"\\|?*\x00-\x1f]' -or
            $entry.Value -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Invalid file entry in package checksums.'
        }
        $output = Join-Path $Destination $relative
        [void][IO.Directory]::CreateDirectory((Split-Path $output -Parent))
        Copy-Item -LiteralPath (Join-Path $Source $relative) -Destination $output
    }
    Copy-Item -LiteralPath $ChecksumFile -Destination (Join-Path $Destination 'checksums.json')
}

function Confirm-PackageFiles([string]$Verifier, [string]$Directory) {
    & $Verifier --verify-package $Directory
    if ($LASTEXITCODE -ne 0) {
        throw "Release files do not match the extracted package: $Directory"
    }
    & (Join-Path $Directory 'spearmint.exe') --version
    if ($LASTEXITCODE -ne 0) {
        throw "The release executable did not start: $Directory"
    }
}

function Get-PanelTask {
    Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
}

function Get-PanelListener([string]$Executable) {
    Get-NetTCPConnection -LocalAddress $Bind -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path -eq $Executable } |
        Select-Object -First 1
}

function Assert-PanelPortFree {
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @($Bind, '0.0.0.0', '::') }) {
        throw "The local panel port $Port is already in use."
    }
}

function Get-HealthCertificatePin([string]$Path) {
    $leaf = [regex]::Match([IO.File]::ReadAllText($Path),
        '-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    if (-not $leaf.Success) {
        throw 'The configured TLS certificate must contain a PEM certificate.'
    }
    [Convert]::ToBase64String([Convert]::FromBase64String($leaf.Groups[1].Value))
}

function Initialize-PanelHealthCheck {
    # Older installers may already have loaded SpearmintPanelUpgradeHealth in this session.
    if (-not ('SpearmintPanelAddressReadiness' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

public static class SpearmintPanelAddressReadiness
{
    public static bool Ready(string address, int port, string authority, string hostname, string expectedCertificate, bool webEntry)
    {
        try
        {
            using (var client = new TcpClient())
            {
                var connection = client.BeginConnect(IPAddress.Parse(address), port, null, null);
                using (var ready = connection.AsyncWaitHandle)
                {
                    if (!ready.WaitOne(1500))
                        return false;
                    client.EndConnect(connection);
                }
                client.ReceiveTimeout = client.SendTimeout = 1500;
                using (var stream = client.GetStream())
                {
                    if (String.IsNullOrEmpty(expectedCertificate))
                        return Check(stream, authority, webEntry);
                    using (var tls = new SslStream(stream, false, (sender, certificate, chain, errors) =>
                        certificate != null && Convert.ToBase64String(certificate.GetRawCertData()) == expectedCertificate))
                    {
                        tls.AuthenticateAsClient(hostname);
                        return Check(tls, authority, webEntry);
                    }
                }
            }
        }
        catch (SocketException) { return false; }
        catch (IOException) { return false; }
        catch (AuthenticationException) { return false; }
    }

    private static bool Check(Stream stream, string authority, bool webEntry)
    {
        // The application requires the configured Host exactly, without an implicit default port.
        var path = webEntry ? "/" : "/healthz";
        var request = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.0\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n");
        stream.Write(request, 0, request.Length);
        using (var response = new StreamReader(stream))
        {
            var status = response.ReadLine();
            if (status == null || !(status.StartsWith("HTTP/1.1 200 ") || status.StartsWith("HTTP/1.0 200 ")))
                return false;
            bool html = false;
            string line;
            while ((line = response.ReadLine()) != null && line.Length != 0)
            {
                if (webEntry && line.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                    html = String.Equals(line.Substring(13).Split(';')[0].Trim(), "text/html", StringComparison.OrdinalIgnoreCase);
            }
            return line != null && (webEntry ? html : response.ReadToEnd() == "{\"status\":\"ok\"}");
        }
    }
}
'@
    }
}

function Wait-PanelReady([string]$Executable, [switch]$CheckWeb) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $listener = Get-PanelListener $Executable
        if ($listener -and (Get-PanelTask).State -eq 'Running' -and
            [SpearmintPanelAddressReadiness]::Ready($Bind, $Port, $uri.Authority, $uri.DnsSafeHost, $certificatePin, $false) -and
            (-not $CheckWeb -or [SpearmintPanelAddressReadiness]::Ready($Bind, $Port, $uri.Authority, $uri.DnsSafeHost, $certificatePin, $true)) -and
            (Get-PanelListener $Executable).OwningProcess -eq $listener.OwningProcess) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 25)
    $false
}

function Stop-PanelTask($Task, [string]$Executable) {
    if ($Task.State -in @('Running', 'Queued')) {
        Stop-ScheduledTask -InputObject $Task
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-PanelTask).State -in @('Running', 'Queued') -or (Get-PanelListener $Executable)) {
        if ($timer.Elapsed.TotalSeconds -ge 25) {
            throw 'The scheduled panel did not stop.'
        }
        Start-Sleep -Milliseconds 250
    }
}

function Get-PanelOriginUri([string]$Value) {
    $parsed = $null
    if (-not [uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne 'https' -or
        $parsed.Port -eq 0 -or $Value -cne $parsed.GetComponents([UriComponents]::SchemeAndServer, [UriFormat]::UriEscaped)) {
        throw 'Enter the canonical HTTPS origin, including a port only if it differs from 443.'
    }
    $parsed
}

function Assert-PackagedTask($Task) {
    if (-not $Task -or $Task.Actions.Count -ne 1 -or $Task.Actions[0].Arguments -cne $arguments -or
        -not (Test-TaskOwner $Task.Principal.UserId $identity) -or
        $Task.Principal.RunLevel -ne 'Limited' -or $Task.Principal.LogonType -ne $TaskLogonType) {
        throw 'The scheduled task does not match this installation. Check its account, logon type and arguments.'
    }
}

function Save-UpgradeRecovery([string]$PreviousCommit, [bool]$WasRunning, [string]$NodeId) {
    $record = @{
        task = $TaskName; previous = $PreviousCommit; target = $manifest.commit; running = $WasRunning; node_id = $NodeId
        origin = $Origin; schema = [int]$manifest.schema; package_checksums_sha256 = $packageSha256
    }
    $temporary = "$recoveryFile.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $data = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress))
            $stream.Write($data, 0, $data.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        [IO.File]::Move($temporary, $recoveryFile)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary }
    }
}

function Confirm-StagedPackage([string]$Directory) {
    if ($packageSha256) {
        $digest = (Get-FileHash -LiteralPath (Join-Path $Directory 'checksums.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne $packageSha256) {
            throw 'The staged package checksum manifest changed. Run the upgrade preflight again.'
        }
    }
}

function Read-UpgradeRecovery {
    $item = Get-Item -LiteralPath $recoveryFile -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The upgrade recovery record must be a regular file.'
    }
    $record = Get-Content -LiteralPath $recoveryFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($record.task -isnot [string] -or $record.task -ne $TaskName -or
        $record.previous -isnot [string] -or $record.previous -cnotmatch '\A[a-f0-9]{40}\z' -or
        $record.target -isnot [string] -or $record.target -cnotmatch '\A[a-f0-9]{40}\z' -or $record.running -isnot [bool] -or
        ($record.PSObject.Properties['node_id'] -and ($record.node_id -isnot [string] -or $record.node_id -cnotmatch '\Aspm1-[a-f0-9]{64}\z'))) {
        throw 'The upgrade recovery record does not match this scheduled task.'
    }
    if ($record.PSObject.Properties['origin'] -or $record.PSObject.Properties['schema']) {
        if (-not $record.node_id -or $record.origin -isnot [string] -or
            ($record.schema -isnot [int] -and $record.schema -isnot [long]) -or $record.schema -lt 1 -or
            $record.schema -gt [int]::MaxValue) {
            throw 'The upgrade recovery record has an invalid origin or schema.'
        }
        $null = Get-PanelOriginUri $record.origin
    }
    if ($record.PSObject.Properties['package_checksums_sha256'] -and
        (-not $record.origin -or $record.package_checksums_sha256 -isnot [string] -or
         $record.package_checksums_sha256 -cnotmatch '\A[a-f0-9]{64}\z')) {
        throw 'The upgrade recovery record has an invalid package checksum manifest digest.'
    }
    $record
}

function Restore-PanelUpgrade {
    $record = Read-UpgradeRecovery
    if ($manifest.commit -cne $record.target) {
        throw "Use the package for interrupted upgrade commit $($record.target) to recover."
    }
    if ($record.package_checksums_sha256 -and $packageSha256 -cne $record.package_checksums_sha256) {
        throw 'Use the native package from the interrupted upgrade. Its checksum manifest does not match this package.'
    }
    if ($record.origin -and $Origin -cne $record.origin) {
        throw 'Use the HTTPS origin from the upgrade recovery record.'
    }
    $previous = Join-Path $releases $record.previous
    $target = Join-Path $releases $record.target
    $previousExecutable = Join-Path $previous 'spearmint.exe'
    $task = Get-PanelTask
    Assert-PackagedTask $task
    $action = $task.Actions[0]
    if ($action.WorkingDirectory -notin @($previous, $target) -or
        $action.Execute -ne (Join-Path $action.WorkingDirectory 'spearmint.exe')) {
        throw 'The scheduled task changed during the upgrade.'
    }
    if (-not (Test-Path -LiteralPath $previousExecutable -PathType Leaf)) {
        throw 'The previous release executable is missing.'
    }
    if ($record.node_id) {
        $plan = & $previousExecutable --state-dir $StateDirectory --origin $Origin migrate --plan
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not read the current node state with the previous release. Follow the backup and recovery instructions.'
        }
        $plan = ($plan -join "`n") | ConvertFrom-Json
        if ($plan.node_id -cne $record.node_id) {
            throw 'The current node state does not match the upgrade recovery record.'
        }
        if ($plan.migration_required -isnot [bool] -or $plan.migration_required) {
            throw 'The previous release cannot use the current database schema. Follow the backup and recovery instructions.'
        }
        if ($record.schema -and $plan.current_schema -ne $record.schema) {
            throw 'The database schema changed since the upgrade began. Follow the backup and recovery instructions.'
        }
    }
    if ($action.Execute -eq $previousExecutable) {
        if (($record.running -and $task.State -eq 'Running' -and (Wait-PanelReady $previousExecutable -CheckWeb)) -or
            (-not $record.running -and $task.State -eq 'Ready' -and -not (Get-PanelListener $previousExecutable))) {
            Remove-Item -LiteralPath $recoveryFile
            Write-Output "Restored: $previous"
            return
        }
    }
    Stop-PanelTask $task $action.Execute
    if ($action.Execute -ne $previousExecutable) {
        $action = New-ScheduledTaskAction -Execute $previousExecutable -Argument $arguments -WorkingDirectory $previous
        Set-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action | Out-Null
    }
    if ($record.running) {
        Assert-PanelPortFree
        Start-ScheduledTask -TaskName $TaskName -TaskPath '\'
        if (-not (Wait-PanelReady $previousExecutable -CheckWeb)) {
            throw 'The previous panel did not pass its local health and Web entry checks.'
        }
    } elseif ((Get-PanelTask).State -ne 'Ready') {
        throw 'The previous panel task could not be restored to its stopped state.'
    }
    Remove-Item -LiteralPath $recoveryFile
    Write-Output "Restored: $previous"
}

if ($PSCmdlet.ParameterSetName -eq 'RecoveryStatus') {
    if (-not $UpgradeRecoveryStatus -or @($PSBoundParameters.Keys | Where-Object { $_ -notin @('UpgradeRecoveryStatus', 'InstallDirectory', 'TaskName') }).Count) {
        throw 'UpgradeRecoveryStatus accepts only InstallDirectory and TaskName.'
    }
    $directory = Get-FullFileSystemPath $InstallDirectory
    try {
        $statusLock = [IO.File]::Open((Join-Path $directory 'install.lock'), 'OpenOrCreate', 'Read', 'Read')
    } catch [IO.DirectoryNotFoundException] {
        Write-Output 'SPEARMINT_UPGRADE_RECOVERY={"pending":false}'
        return
    } catch [IO.IOException] {
        # Win32 ERROR_SHARING_VIOLATION from the installer's exclusive open.
        if (($_.Exception.GetBaseException().HResult -band 0xffff) -ne 32) { throw }
        Write-Output 'SPEARMINT_UPGRADE_RECOVERY={"busy":true}'
        return
    }
    try {
        $recoveryFile = Join-Path $directory 'upgrade-recovery.json'
        if (Test-Path -LiteralPath $recoveryFile) {
            $record = Read-UpgradeRecovery
            $status = [ordered]@{ pending = $true; previous_commit = $record.previous; candidate_commit = $record.target; panel_was_running = $record.running }
            if ($record.node_id) { $status['node_id'] = $record.node_id }
            if ($record.origin) { $status['origin'] = $record.origin; $status['schema'] = $record.schema }
            if ($record.package_checksums_sha256) { $status['package_checksums_sha256'] = $record.package_checksums_sha256 }
            if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'X64') {
                $status['target'] = 'windows-amd64'
            }
        } else {
            $status = @{ pending = $false }
        }
        Write-Output "SPEARMINT_UPGRADE_RECOVERY=$($status | ConvertTo-Json -Compress)"
    } finally {
        $statusLock.Dispose()
    }
    return
}
if (@($StageOnly, $Upgrade, $CheckUpgrade, $RecoverUpgrade).Where({ $_ }).Count -gt 1) {
    throw 'Choose one of StageOnly, Upgrade, CheckUpgrade, and RecoverUpgrade.'
}
if ($PSBoundParameters.ContainsKey('VerifyBackup') -and (-not $upgradeMode -or -not $VerifyBackup)) {
    throw 'VerifyBackup requires Upgrade or CheckUpgrade and an existing backup directory.'
}
if ($ExpectedBackupSha256 -and -not $VerifyBackup) {
    throw 'ExpectedBackupSha256 requires VerifyBackup.'
}
if (($ExpectedNode -or $ExpectedCommit -or $ExpectedCurrentCommit) -and -not $upgradeMode) {
    throw 'ExpectedNode, ExpectedCommit and ExpectedCurrentCommit require Upgrade or CheckUpgrade.'
}
if ($ExpectedPackageSha256 -and -not $upgradeMode) {
    throw 'ExpectedPackageSha256 requires Upgrade or CheckUpgrade.'
}
if ($KeepStopped -and -not $upgradeMode) {
    throw 'KeepStopped requires Upgrade or CheckUpgrade.'
}
$uri = Get-PanelOriginUri $Origin
if ([bool]$Certificate -ne [bool]$PrivateKey) {
    throw 'Native HTTPS requires both Certificate and PrivateKey.'
}
if ($Bind -ne '127.0.0.1') {
    $bindAddress = $null
    if (-not [Net.IPAddress]::TryParse($Bind, [ref]$bindAddress) -or
        $bindAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $Bind -cne $bindAddress.ToString()) {
        throw 'Bind must be 127.0.0.1 or an explicit private IPv4 address.'
    }
    $octets = $bindAddress.GetAddressBytes()
    if (-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -in 16..31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168))) {
        throw 'Bind must be 127.0.0.1 or an explicit private IPv4 address.'
    }
    if (-not $Certificate) { throw 'A LAN binding requires Certificate and PrivateKey.' }
    if (-not $StageOnly -and -not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Bind -ErrorAction SilentlyContinue)) {
        throw "The LAN address $Bind is not assigned to this machine."
    }
}
$StateDirectory = Get-FullFileSystemPath $StateDirectory
$panelConfig = @('--state-dir', $StateDirectory, '--origin', $Origin)
$arguments = @('--state-dir', (Quote-TaskValue $StateDirectory), '--origin', (Quote-TaskValue $Origin))
if ($WebDirectory) {
    $WebDirectory = Get-FullFileSystemPath $WebDirectory
    $panelConfig += @('--web-dir', $WebDirectory)
    $arguments += @('--web-dir', (Quote-TaskValue $WebDirectory))
}
if ($GroveCA) {
    $GroveCA = Get-FullFileSystemPath $GroveCA
    $panelConfig += @('--grove-ca', $GroveCA)
    $arguments += @('--grove-ca', (Quote-TaskValue $GroveCA))
}
$arguments += @('serve', '--bind', $Bind, '--port', [string]$Port)
if ($Certificate) {
    $Certificate = Get-FullFileSystemPath $Certificate
    $PrivateKey = Get-FullFileSystemPath $PrivateKey
    if (-not (Test-Path -LiteralPath $Certificate -PathType Leaf) -or
        -not (Test-Path -LiteralPath $PrivateKey -PathType Leaf)) {
        throw 'Provide the certificate and private key files for native HTTPS.'
    }
    $arguments += @('--tls-cert', (Quote-TaskValue $Certificate), '--tls-key', (Quote-TaskValue $PrivateKey))
}
$arguments = $arguments -join ' '

$bundle = Split-Path $PSScriptRoot -Parent
$InstallDirectory = Get-FullFileSystemPath $InstallDirectory
if ($TaskLogonType -eq 'S4U') {
    foreach ($path in @($InstallDirectory, $StateDirectory, $WebDirectory, $Certificate, $PrivateKey, $GroveCA)) {
        if ($path) { Assert-LocalTaskPath $path }
    }
}
if ((Test-WithinPath $InstallDirectory $bundle) -or (Test-WithinPath $InstallDirectory $StateDirectory) -or
    (Test-WithinPath $StateDirectory $InstallDirectory) -or (Test-WithinPath $StateDirectory $bundle)) {
    throw 'Choose separate directories for the extracted package, installed releases, and node state.'
}
$manifest = Get-Content -LiteralPath (Join-Path $bundle 'build-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.os -ne 'windows' -or $manifest.commit -cnotmatch '^[a-f0-9]{40}$') {
    throw 'Extract a complete Windows native package.'
}
if ($ExpectedCommit -and $manifest.commit -cne $ExpectedCommit) {
    throw 'The package commit does not match the selected candidate.'
}
$checksums = Join-Path $bundle 'checksums.json'
$packageBinary = Join-Path $bundle 'spearmint.exe'
if (-not (Test-Path -LiteralPath $checksums -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $bundle 'web\index.html') -PathType Leaf)) {
    throw 'The package is missing its Web files or checksums.'
}
if (-not (Test-Path -LiteralPath $packageBinary -PathType Leaf)) {
    throw 'The package is missing spearmint.exe.'
}
$packageSha256 = $null
if ($upgradeMode -or $RecoverUpgrade) {
    $packageSha256 = (Get-FileHash -LiteralPath $checksums -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedPackageSha256 -and $packageSha256 -cne $ExpectedPackageSha256) {
        throw 'The package checksum manifest changed. Run the upgrade preflight again.'
    }
}
$preflight = $panelConfig + 'validate-config'
if ($Certificate) {
    $preflight += @('--tls-cert', $Certificate, '--tls-key', $PrivateKey)
}
if ($JoinGrove) {
    $JoinGrove = Get-FullFileSystemPath $JoinGrove
    if (-not (Test-Path -LiteralPath $JoinGrove -PathType Leaf)) {
        throw 'Use a Grove invitation JSON file.'
    }
    $preflight += @('--join-grove', $JoinGrove)
}
& $packageBinary @preflight
if ($LASTEXITCODE -ne 0) {
    throw 'Panel configuration validation failed. See the Spearmint error above.'
}
$releases = [IO.Directory]::CreateDirectory((Join-Path $InstallDirectory 'releases')).FullName
$release = Join-Path $releases $manifest.commit
$binary = Join-Path $release 'spearmint.exe'
$recoveryFile = Join-Path $InstallDirectory 'upgrade-recovery.json'
$lock = [IO.File]::Open((Join-Path $InstallDirectory 'install.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pendingRecovery = Test-Path -LiteralPath $recoveryFile
    if ($RecoverUpgrade) {
        if (-not $pendingRecovery) {
            Write-Output 'No interrupted upgrade to recover.'
            return
        }
        Initialize-PanelHealthCheck
        $certificatePin = if ($Certificate) { Get-HealthCertificatePin $Certificate }
        Restore-PanelUpgrade
        return
    }
    if ($pendingRecovery) {
        throw 'An upgrade was interrupted. Use -RecoverUpgrade with the same installation parameters.'
    }
    $task = $null
    if (-not $StageOnly) {
        $task = Get-PanelTask
        if ($task) { Assert-PackagedTask $task }
        if ($upgradeMode) {
            if (-not $task -or $task.State -notin @('Ready', 'Running')) {
                throw 'Upgrade requires an existing packaged task that is ready or running.'
            }
            $previousAction = $task.Actions[0]
            $previousRelease = $previousAction.WorkingDirectory
            if (-not $previousRelease -or (Split-Path $previousRelease -Parent) -ne $releases -or
                (Split-Path $previousRelease -Leaf) -cnotmatch '^[a-f0-9]{40}$' -or
                $previousAction.Execute -ne (Join-Path $previousRelease 'spearmint.exe') -or
                -not (Test-Path -LiteralPath $previousAction.Execute -PathType Leaf)) {
                throw 'The task does not identify an installed Spearmint release.'
            }
            $previousManifest = Get-Content -LiteralPath (Join-Path $previousRelease 'build-manifest.json') -Raw | ConvertFrom-Json
            if ($previousManifest.os -ne 'windows' -or $previousManifest.commit -cne (Split-Path $previousRelease -Leaf) -or
                [string]$manifest.schema -cnotmatch '^[1-9][0-9]*$' -or [string]$previousManifest.schema -cne [string]$manifest.schema) {
                throw 'This upgrade changes the database schema or has an invalid manifest. Follow the backup and migration instructions.'
            }
            if ($ExpectedCurrentCommit -and $previousManifest.commit -cne $ExpectedCurrentCommit) {
                throw 'The installed commit changed. Run the upgrade preflight again.'
            }
        } elseif ($task) {
            if ($task.Actions[0].Execute -ne $binary -or $task.Actions[0].WorkingDirectory -ne $release) {
                throw 'A different scheduled task already uses this name. Use its current upgrade procedure.'
            }
        } elseif ($TaskLogonType -eq 'S4U' -and
            -not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Registering an S4U startup task requires administrator rights on this host.'
        }
    }
    if (Test-Path -LiteralPath $release) {
        Confirm-StagedPackage $release
        Confirm-PackageFiles $packageBinary $release
    } else {
        $temporary = Join-Path $releases ('.install-' + [guid]::NewGuid().ToString('N'))
        if (-not (Test-WithinPath $temporary $releases) -or -not (Test-WithinPath $release $releases)) {
            throw 'Invalid package installation path.'
        }
        try {
            Copy-PackageFiles $bundle $temporary $checksums
            Confirm-StagedPackage $temporary
            Confirm-PackageFiles $packageBinary $temporary
            [IO.Directory]::Move($temporary, $release)
        } finally {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Recurse -Force
            }
        }
    }
    Push-Location -LiteralPath $release
    try {
        & $binary @preflight --check-web
        if ($LASTEXITCODE -ne 0) {
            throw 'Web or panel configuration validation failed. See the Spearmint error above.'
        }
    } finally {
        Pop-Location
    }
    if ($upgradeMode) {
        $plan = & $binary --state-dir $StateDirectory --origin $Origin migrate --plan
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not read the existing panel state. Check StateDirectory.'
        }
        $plan = ($plan -join "`n") | ConvertFrom-Json
        if ($plan.node_id -isnot [string] -or $plan.node_id -cnotmatch '\Aspm1-[a-f0-9]{64}\z' -or $plan.current_schema -ne $manifest.schema -or
            $plan.target_schema -ne $manifest.schema -or $plan.migration_required -ne $false) {
            throw 'The existing database schema does not match the package. Follow the backup and migration instructions.'
        }
        if ($ExpectedNode -and $plan.node_id -cne $ExpectedNode) {
            throw 'The existing database does not belong to the selected Node ID.'
        }
        $backupSha256 = $null
        if ($VerifyBackup) {
            $report = & $binary verify-backup (Get-FullFileSystemPath $VerifyBackup)
            if ($LASTEXITCODE -ne 0) {
                throw 'The upgrade backup did not pass verification.'
            }
            $report = ($report -join "`n") | ConvertFrom-Json
            if ($report.node_id -cne $plan.node_id -or $report.restore_compatible -ne $true) {
                throw 'The upgrade backup belongs to a different node or schema.'
            }
            $backupSha256 = $report.backup_sha256
            if ($ExpectedBackupSha256 -and $backupSha256 -cne $ExpectedBackupSha256) {
                throw 'The upgrade backup changed. Run the upgrade preflight again.'
            }
        }
        Initialize-PanelHealthCheck
        $certificatePin = if ($Certificate) { Get-HealthCertificatePin $Certificate }
        $wasRunning = $task.State -eq 'Running'
        if ($KeepStopped -and $wasRunning) {
            throw 'Stop the existing panel before using KeepStopped.'
        }
        if ($wasRunning -and -not (Wait-PanelReady $previousAction.Execute)) {
            throw 'The current panel did not pass its local health check.'
        }
        if (-not $wasRunning) {
            Assert-PanelPortFree
        }
        Confirm-StagedPackage $release
        if ($CheckUpgrade) {
            Write-Output "Upgrade checks passed: $($previousManifest.commit) -> $($manifest.commit)"
            $receipt = @{
                version = 1
                node_id = $plan.node_id
                origin = $Origin
                previous_commit = $previousManifest.commit
                candidate_commit = $manifest.commit
                schema = [int]$manifest.schema
                panel_running = $wasRunning
                keep_stopped = [bool]$KeepStopped
                backup_verified = [bool]$VerifyBackup
                package_checksums_sha256 = $packageSha256
            }
            if ($backupSha256) { $receipt.backup_sha256 = $backupSha256 }
            if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'X64') { $receipt.target = 'windows-amd64' }
            Write-Output "SPEARMINT_UPGRADE_PREFLIGHT=$($receipt | ConvertTo-Json -Compress)"
            return
        }
        if ($KeepStopped -and $previousAction.Execute -eq $binary) {
            Write-Output "Already installed and stopped: $release"
            return
        }
        if (-not $wasRunning -or $previousAction.Execute -ne $binary) {
            Save-UpgradeRecovery $previousManifest.commit $wasRunning $plan.node_id
            try {
                Stop-PanelTask $task $previousAction.Execute
                $action = New-ScheduledTaskAction -Execute $binary -Argument $arguments -WorkingDirectory $release
                Set-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action | Out-Null
                if ($KeepStopped) {
                    if ((Get-PanelTask).State -ne 'Ready' -or (Get-PanelListener $binary)) {
                        throw 'The panel did not remain stopped during the upgrade.'
                    }
                } else {
                    Start-ScheduledTask -TaskName $TaskName -TaskPath '\'
                    if (-not (Wait-PanelReady $binary -CheckWeb)) {
                        throw 'The new panel did not pass its local health and Web entry checks.'
                    }
                }
            } catch {
                $failure = $_
                try {
                    Restore-PanelUpgrade
                } catch {
                    throw "Upgrade failed: $($failure.Exception.Message) Rollback failed: $($_.Exception.Message) Use -RecoverUpgrade to retry."
                }
                throw $failure
            }
            Remove-Item -LiteralPath $recoveryFile
            if ($KeepStopped) { Write-Output "Panel remains stopped. Start scheduled task $TaskName when ready." }
        } elseif (-not (Wait-PanelReady $binary -CheckWeb)) {
            throw 'The current panel does not serve its Web entry.'
        }
        Write-Output "Scheduled task: $TaskName"
    } elseif (-not $StageOnly) {
        Initialize-PanelHealthCheck
        $certificatePin = if ($Certificate) { Get-HealthCertificatePin $Certificate }
        if ($task.State -notin @('Running', 'Queued')) {
            Assert-PanelPortFree
        }
        if ($JoinGrove) {
            $seedReceipt = & $binary @panelConfig setup-link --renew-if-expired --join-grove $JoinGrove --seed-receipt
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not prepare the Grove first-run link. Check the invitation and the node state.'
            }
        }
        $createdTask = $false
        try {
            if (-not $task) {
                $action = New-ScheduledTaskAction -Execute $binary -Argument $arguments -WorkingDirectory $release
                $trigger = New-PanelTaskTrigger $identity
                $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType $TaskLogonType -RunLevel Limited
                $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
                    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
                $task = Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action -Trigger $trigger `
                    -Principal $principal -Settings $settings -Description 'Spearmint native management panel'
                $createdTask = $true
            }
            if ($task.State -notin @('Running', 'Queued')) {
                Start-ScheduledTask -InputObject $task
            }
            if (-not (Wait-PanelReady $binary -CheckWeb)) {
                $result = (Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue).LastTaskResult
                throw "The installed panel did not pass its local health and Web entry checks on port $Port. Task Scheduler last result: $result."
            }
        } catch {
            $failure = $_
            if ($createdTask) {
                try {
                    $currentTask = Get-PanelTask
                    if ($currentTask) {
                        Assert-PackagedTask $currentTask
                        if ($currentTask.Actions[0].Execute -ne $binary -or $currentTask.Actions[0].WorkingDirectory -ne $release) {
                            throw 'The scheduled task changed during installation.'
                        }
                        Stop-PanelTask $currentTask $binary
                        Unregister-ScheduledTask -InputObject $currentTask -Confirm:$false
                    }
                } catch {
                    throw "Installation failed: $($failure.Exception.Message) Task cleanup failed: $($_.Exception.Message)"
                }
            }
            throw $failure
        }
        Write-Output "Scheduled task: $TaskName"
    }
    Write-Output "Installed: $release"
    Write-Output "Node state: $StateDirectory"
    if (-not $StageOnly -and -not $upgradeMode -and (-not $JoinGrove -or $OpenSetup)) {
        try {
            $setupAction = if ($OpenSetup) { '--open' } else { '--status' }
            & $binary --state-dir $StateDirectory --origin $Origin setup-link $setupAction
            if ($LASTEXITCODE -ne 0) {
                throw 'The first-run status command failed.'
            }
        } catch {
            Write-Warning 'Could not read first-run status. Check the node state directory and run spearmint setup-link --status as the panel account.'
        }
    }
    if ($JoinGrove) {
        Write-Output $seedReceipt
    }
} finally {
    $lock.Dispose()
}
