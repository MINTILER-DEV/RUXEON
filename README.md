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
- CLI commands for `run`, `trace`, and `shell` scaffolding.

Later phases will add Linux syscall dispatch, rootfs translation, dynamic linker support, process scheduling, and terminal handling.

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

`run` and `trace` currently execute until the guest exits with Linux syscall `exit`/`exit_group`, reaches an unsupported syscall, or hits the step limit.

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
