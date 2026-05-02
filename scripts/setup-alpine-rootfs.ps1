param(
    [string]$Rootfs = ".\rootfs\alpine",
    [string]$Version = "3.20.3",
    [string]$Arch = "x86_64"
)

$ErrorActionPreference = "Stop"

$majorMinor = ($Version -split "\.")[0..1] -join "."
$archive = "alpine-minirootfs-$Version-$Arch.tar.gz"
$url = "https://dl-cdn.alpinelinux.org/alpine/v$majorMinor/releases/$Arch/$archive"
$downloadDir = Join-Path $PSScriptRoot "..\target\rootfs-downloads"
$archivePath = Join-Path $downloadDir $archive

New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
New-Item -ItemType Directory -Force -Path $Rootfs | Out-Null

if (!(Test-Path $archivePath)) {
    Write-Host "Downloading $url"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archivePath
}

Write-Host "Extracting $archivePath to $Rootfs"
tar -xzf $archivePath -C $Rootfs

Write-Host "Alpine rootfs ready: $Rootfs"
Write-Host "Try: cargo run -p ruxeon-cli -- run --rootfs $Rootfs /bin/busybox sh"
