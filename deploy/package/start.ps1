param(
    [string]$Origin = 'https://localhost:8443',
    [int]$Port = 8765,
    [string]$Bind = '127.0.0.1',
    [string]$Certificate,
    [string]$PrivateKey,
    [ValidateNotNullOrEmpty()]
    [string]$GroveCA,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'spearmint'),
    [string]$JoinGrove,
    [switch]$OpenSetup
)
$ErrorActionPreference = 'Stop'
if ([bool]$Certificate -ne [bool]$PrivateKey) {
    throw 'Native HTTPS requires both Certificate and PrivateKey.'
}
$env:SPEARMINT_ORIGIN = $Origin
$env:SPEARMINT_STATE_DIR = $StateDirectory
$binary = Join-Path (Split-Path $PSScriptRoot -Parent) 'spearmint.exe'
$arguments = @('serve', '--port', $Port, '--bind', $Bind)
if ($GroveCA) {
    $arguments = @('--grove-ca', $GroveCA) + $arguments
}
if ($Certificate) {
    $arguments += @('--tls-cert', $Certificate, '--tls-key', $PrivateKey)
}
if ($OpenSetup) {
    $arguments += '--open-setup'
}
if ($JoinGrove) {
    $arguments += @('--join-grove', $JoinGrove)
}
& $binary @arguments
exit $LASTEXITCODE
