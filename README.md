# RUXEON

Ruxeon is a Rust-based Linux user-mode runtime for Windows. The first milestone loads ELF64 Linux x86_64 binaries into guest memory and interprets a focused subset of x86_64 instructions.

The long-term target is:

```powershell
ruxeon run --rootfs ./rootfs /bin/bash
```

## Current Status

Implemented:

- Rust workspace with the requested crate layout.
- ELF64 little-endian x86_64 parser and loader.
- PT_LOAD segment mapping with page permission metadata.
- Linux-style initial stack setup with `argv`, `envp`, and auxv.
- Guest virtual memory model.
- x86_64 interpreter for core integer, branch, stack, and syscall instructions.
- Linux syscall dispatcher with fd table, stdio, regular file handling, errno returns, and core process syscalls.
- Virtual Linux rootfs resolver with safe path normalization plus `/dev` and `/proc` special files.
- PT_INTERP/PT_DYNAMIC parsing and dynamic-loader entry setup with `AT_BASE`, `AT_ENTRY`, `AT_PHDR`, and related auxv values.
- Bash-oriented syscall plumbing: pipes, fd duplication/control, polling, directory reads, time/sysinfo, uid/gid/process-group stubs, signal stubs, and `execve` reload.
- CLI commands for `run`, `trace`, and `shell` scaffolding.

Later phases will deepen dynamic linker compatibility, add a cooperative child scheduler, and improve terminal handling.

## Build

```powershell
cargo build
```

## Test

```powershell
cargo test
```

## CLI

```powershell
cargo run -p ruxeon-cli -- run ./program
cargo run -p ruxeon-cli -- run --rootfs ./rootfs /bin/bash
cargo run -p ruxeon-cli -- shell --rootfs ./rootfs
cargo run -p ruxeon-cli -- trace ./program
```

`run` and `trace` currently execute guest syscalls through the dispatcher. Tiny static programs that use basic syscalls such as `write`, `exit`, `brk`, `mmap`, and file open/read/write paths can run within the current instruction subset.

Dynamically linked ELFs are recognized through `PT_INTERP`; when `--rootfs` is provided, Ruxeon loads the requested Linux dynamic linker and transfers initial execution to it with realistic auxv metadata. Running full glibc/ld-linux workloads still requires later compatibility work in the CPU and syscall layers.

`execve` reloads a new ELF into the current process and rebuilds guest memory/stack while preserving non-close-on-exec file descriptors. `fork`/`clone`/`vfork` currently return a synthetic child PID to the parent; cooperative child scheduling is reserved for the process model phase.

## Fixtures

Tiny Linux fixture binaries should be generated locally and kept out of git unless they are very small and intentionally reviewed. A simple C fixture:

```c
#include <unistd.h>

int main(void) {
    write(1, "hello\n", 6);
    return 0;
}
```

Compile on a Linux toolchain:

```bash
x86_64-linux-gnu-gcc -static hello.c -o hello-static
x86_64-linux-gnu-gcc hello.c -o hello-dynamic
```

## License

RUXEON is licensed under the MIT License. See [LICENSE](LICENSE).
