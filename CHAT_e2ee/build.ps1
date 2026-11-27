$ErrorActionPreference = 'Stop'

$noiseJar = Join-Path $env:USERPROFILE '.m2\repository\com\github\auties00\noise-java\1.2\noise-java-1.2.jar'
if (-not (Test-Path -LiteralPath $noiseJar)) {
    throw "Noise dependency not found: $noiseJar"
}

$sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src\main\java') -Filter '*.java' -Recurse)
if ($sourceFiles.Count -eq 0) {
    throw 'No Java source files found.'
}

$classesDirectory = Join-Path $PSScriptRoot 'target\classes'
$appClass = Join-Path $classesDirectory 'org\example\App.class'
$needsBuild = -not (Test-Path -LiteralPath $appClass)
if (-not $needsBuild) {
    $classTime = (Get-Item -LiteralPath $appClass).LastWriteTimeUtc
    $needsBuild = @($sourceFiles | Where-Object { $_.LastWriteTimeUtc -gt $classTime }).Count -gt 0
}

if ($needsBuild) {
    New-Item -ItemType Directory -Force -Path $classesDirectory | Out-Null
    & javac --release 17 -Xlint:all -Werror -cp $noiseJar -d $classesDirectory @($sourceFiles.FullName)
    if ($LASTEXITCODE -ne 0) {
        throw "Java compilation failed with exit code $LASTEXITCODE."
    }
    Write-Host 'Project compiled.'
}
