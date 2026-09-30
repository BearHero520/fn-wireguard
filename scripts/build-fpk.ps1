param(
    [ValidateSet('amd64','arm64')][string]$Architecture = 'amd64',
    [string]$Fnpack = '',
    [switch]$SkipFrontendBuild
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$templateRoot = Join-Path $projectRoot 'packaging/fnos'
$sourceInfo = [IO.File]::ReadAllText((Join-Path $projectRoot 'internal/buildinfo/info.go'))
$versionMatch = [regex]::Match($sourceInfo, 'Version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"')
$templateManifest = [IO.File]::ReadAllText((Join-Path $templateRoot 'manifest'))
if (-not $versionMatch.Success -or -not [regex]::IsMatch($templateManifest, '(?m)^version=' + [regex]::Escape($versionMatch.Groups[1].Value) + '\s*$')) {
    throw 'Manifest version must match internal/buildinfo.Version before building an FPK'
}
$outputRoot = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$packageRoot = Join-Path $outputRoot ('fpk-staging-' + $Architecture + '-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $packageRoot | Out-Null
Copy-Item -Path (Join-Path $templateRoot '*') -Destination $packageRoot -Recurse -Force
# Staging has a fresh directory per build. Old web assets cannot enter a new package.
if (-not $SkipFrontendBuild) {
    Push-Location (Join-Path $projectRoot 'web')
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    } finally { Pop-Location }
}
New-Item -ItemType Directory -Force -Path (Join-Path $packageRoot 'app/server') | Out-Null
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
Push-Location $projectRoot
try {
    $env:GOOS = 'linux'
    $env:GOARCH = $Architecture
    $env:CGO_ENABLED = '0'
    & go build -trimpath -ldflags '-s -w' -o (Join-Path $packageRoot 'app/server/fn-wireguard') ./cmd/fn-wireguard
    if ($LASTEXITCODE -ne 0) { throw 'Linux backend build failed' }
    & go build -trimpath -ldflags '-s -w' -o (Join-Path $packageRoot 'app/server/fn-wireguard-maintenance') ./cmd/fn-wireguard-maintenance
    if ($LASTEXITCODE -ne 0) { throw 'Linux maintenance tool build failed' }
} finally {
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
    Pop-Location
}
$publicRoot = Join-Path $packageRoot 'app/public'
New-Item -ItemType Directory -Force -Path $publicRoot | Out-Null
Copy-Item -Path (Join-Path $projectRoot 'web/dist/*') -Destination $publicRoot -Recurse -Force
$manifestPath = Join-Path $packageRoot 'manifest'
$manifestText = [IO.File]::ReadAllText($manifestPath)
$platformName = if ($Architecture -eq 'amd64') { 'x86' } else { 'arm' }
$manifestText = [regex]::Replace($manifestText, '(?m)^platform=.*$', "platform=$platformName")
[IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
if (-not $Fnpack) {
    $toolRoot = Join-Path $projectRoot '.tools'
    New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
    $Fnpack = Join-Path $toolRoot 'fnpack-1.2.3.exe'
    if (-not (Test-Path -LiteralPath $Fnpack)) {
        Invoke-WebRequest 'https://static2.fnnas.com/fnpack/fnpack-1.2.3-windows-amd64' -OutFile $Fnpack
    }
}
Push-Location $packageRoot
try {
    & $Fnpack build --directory $packageRoot
    if ($LASTEXITCODE -ne 0) { throw 'fnpack build failed' }
} finally { Pop-Location }
$builtFpk = Join-Path $packageRoot 'fn-wireguard.fpk'
if (-not (Test-Path -LiteralPath $builtFpk)) { throw 'fnpack returned success without an FPK artifact' }
& go run (Join-Path $PSScriptRoot 'fpk-permissions.go') $builtFpk
if ($LASTEXITCODE -ne 0) { throw 'FPK Linux permission normalization failed' }
$releaseFpk = Join-Path $outputRoot ('fn-wireguard-' + $Architecture + '.fpk')
Move-Item -LiteralPath $builtFpk -Destination $releaseFpk -Force
Get-FileHash -LiteralPath $releaseFpk -Algorithm SHA256
# Remove only this successful build's fresh, verified staging directory.
$resolvedStage = [IO.Path]::GetFullPath($packageRoot)
$resolvedOutput = [IO.Path]::GetFullPath($outputRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
if ([IO.Path]::GetDirectoryName($resolvedStage) -ne $resolvedOutput -or
    -not [IO.Path]::GetFileName($resolvedStage).StartsWith('fpk-staging-')) {
    throw 'Refusing to remove a staging directory outside the build output directory'
}
Remove-Item -LiteralPath $resolvedStage -Recurse -Force
$sumLines = Get-ChildItem -LiteralPath $outputRoot -Filter 'fn-wireguard-*.fpk' | Sort-Object Name | ForEach-Object {
    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name
}
[IO.File]::WriteAllLines((Join-Path $outputRoot 'SHA256SUMS.txt'), [string[]]$sumLines, [Text.UTF8Encoding]::new($false))
