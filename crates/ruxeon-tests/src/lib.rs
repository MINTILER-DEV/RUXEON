//! Cross-crate integration test harness.

#[cfg(test)]
mod tests {
    use ruxeon_core::{GuestMemory, MemoryPermission};
    use ruxeon_cpu::{Interpreter, Registers, StepOutcome};
    use ruxeon_linux::{
        LinuxProcess, SyscallContext, SyscallDispatcher, SyscallInput, SyscallOutcome,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn cpu_syscall_dispatcher_runs_write_then_exit() {
        const BASE: u64 = 0x1000;
        let code = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
            0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rel msg]
            0xba, 0x06, 0x00, 0x00, 0x00, // mov edx, 6
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
            0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
            b'h', b'e', b'l', b'l', b'o', b'\n',
        ];
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                BASE,
                0x1000,
                MemoryPermission::READ | MemoryPermission::WRITE | MemoryPermission::EXECUTE,
                Some("code".to_string()),
            )
            .unwrap();
        memory.write_bytes(BASE, &code).unwrap();

        let mut interpreter = Interpreter::new(
            memory,
            Registers {
                rip: BASE,
                rsp: 0x8000,
                ..Registers::default()
            },
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut process = LinuxProcess::new(None);
        process.fd_table_mut().install_buffer(1, output.clone());

        let mut exit = None;
        for _ in 0..16 {
            match interpreter.step().unwrap() {
                StepOutcome::Continue => {}
                StepOutcome::Halted(code) => {
                    exit = Some(code);
                    break;
                }
                StepOutcome::Syscall(trap) => {
                    let outcome = SyscallDispatcher::dispatch(
                        &mut process,
                        &mut SyscallContext {
                            memory: interpreter.memory_mut(),
                        },
                        SyscallInput {
                            number: trap.number,
                            args: trap.args,
                        },
                    );
                    match outcome {
                        SyscallOutcome::Return(value) => {
                            interpreter.registers_mut().rax = value as u64;
                        }
                        SyscallOutcome::Exit(code) => {
                            exit = Some(code);
                            break;
                        }
                        SyscallOutcome::Execve(_) => panic!("unexpected execve"),
                    }
                }
            }
        }

        assert_eq!(exit, Some(0));
        assert_eq!(&*output.lock().unwrap(), b"hello\n");
        assert_eq!(process.trace()[0].name, "write");
        assert_eq!(process.trace()[1].name, "exit");
    }
}
