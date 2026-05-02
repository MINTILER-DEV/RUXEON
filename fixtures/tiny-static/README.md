# Tiny Static Fixtures

This directory documents the fixture strategy without committing large binaries.

Create tiny Linux ELF files on a machine with an x86_64 Linux cross-toolchain:

```bash
cat > hello.c <<'C'
#include <unistd.h>

int main(void) {
    write(1, "hello\n", 6);
    return 0;
}
C

x86_64-linux-gnu-gcc -static hello.c -o hello-static
```

Keep generated binaries local unless a test intentionally needs a tiny checked-in fixture.
