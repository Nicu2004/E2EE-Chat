param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('server', 'run')]
    [string]$Mode,
    [Parameter(Position = 1)]
    [string]$Name,
    [string]$HostName = '127.0.0.1',
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'

if ($Mode -eq 'run' -and ($Name -notmatch '^[A-Za-z0-9_]{1,32}$')) {
    throw 'Usage: .\chat.ps1 run <name>'
}

& (Join-Path $PSScriptRoot 'build.ps1')

$noiseJar = Join-Path $env:USERPROFILE '.m2\repository\com\github\auties00\noise-java\1.2\noise-java-1.2.jar'
$classPath = "$(Join-Path $PSScriptRoot 'target\classes');$noiseJar"

if ($Mode -eq 'server') {
    & java -cp $classPath org.example.App server $Port
    if ($LASTEXITCODE -ne 0) {
        throw "Relay exited with code $LASTEXITCODE."
    }
    return
}

$identityDirectory = Join-Path $env:USERPROFILE '.chat_tofu'
$authorityPrivateKey = Join-Path $identityDirectory 'authority_private.key'
$authorityPublicKey = Join-Path $identityDirectory 'authority_public.key'
$hasPrivateKey = Test-Path -LiteralPath $authorityPrivateKey
$hasPublicKey = Test-Path -LiteralPath $authorityPublicKey
if ($hasPrivateKey -ne $hasPublicKey) {
    throw "Authority key pair is incomplete in $identityDirectory. Restore the missing key; do not create a new authority."
}
if (-not $hasPrivateKey) {
    & java -cp $classPath org.example.App authority-init
    if ($LASTEXITCODE -ne 0) {
        throw "Authority initialization failed with exit code $LASTEXITCODE."
    }
}

& java -cp $classPath org.example.App authority-issue $Name
if ($LASTEXITCODE -ne 0) {
    throw "Certificate issuance failed for $Name with exit code $LASTEXITCODE."
}

& java -cp $classPath org.example.App client $Name $HostName $Port
if ($LASTEXITCODE -ne 0) {
    throw "Client exited with code $LASTEXITCODE."
}
