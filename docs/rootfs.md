# Rootfs Setup

RUXEON resolves guest Linux paths through a host directory passed with `--rootfs`.
The first supported target is an Alpine minirootfs because it is small and easy to
inspect while syscall and dynamic-linker compatibility are still growing.

## Alpine

From PowerShell:

```powershell
.\scripts\setup-alpine-rootfs.ps1 -Rootfs .\rootfs\alpine
cargo run -p ruxeon-cli -- run --rootfs .\rootfs\alpine /bin/busybox sh
cargo run -p ruxeon-cli -- shell --rootfs .\rootfs\alpine
```

The `shell` command starts `/bin/sh`.

Useful direct smoke commands:

```powershell
cargo run -p ruxeon-cli -- run --rootfs .\rootfs\alpine /bin/echo hi
cargo run -p ruxeon-cli -- run --rootfs .\rootfs\alpine /bin/cat /etc/os-release
```

## Debian

Debian rootfs support is the next compatibility target. For now, create or export
a Debian rootfs with WSL, Docker, or `debootstrap`, then pass the extracted
directory to RUXEON:

```powershell
cargo run -p ruxeon-cli -- run --rootfs .\rootfs\debian /bin/sh
```

Large rootfs archives and extracted rootfs directories should stay out of git.
