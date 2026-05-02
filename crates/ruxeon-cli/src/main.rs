use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ruxeon_cpu::{Interpreter, Registers, StepOutcome};
use ruxeon_elf::{ElfImage, LoadedProgram};
use ruxeon_fs::{GuestPath, ResolvedPath, RootFs};
use ruxeon_linux::{LinuxProcess, SyscallContext, SyscallDispatcher, SyscallInput, SyscallOutcome};
use std::{fs, path::PathBuf};

const DEFAULT_MAX_STEPS: u64 = 1_000_000;

#[derive(Debug, Parser)]
#[command(name = "ruxeon", about = "Linux user-mode runtime for Windows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        rootfs: Option<PathBuf>,
        program: PathBuf,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    Shell {
        #[arg(long)]
        rootfs: PathBuf,
    },
    Trace {
        program: PathBuf,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            rootfs,
            program,
            args,
        } => run_program(rootfs, program, args, false),
        Command::Shell { rootfs } => {
            run_program(Some(rootfs), PathBuf::from("/bin/bash"), Vec::new(), false)
        }
        Command::Trace { program, args } => run_program(None, program, args, true),
    }
}

fn run_program(
    rootfs: Option<PathBuf>,
    program: PathBuf,
    args: Vec<String>,
    trace: bool,
) -> Result<()> {
    let host_program = translate_program_path(rootfs.as_ref(), &program);
    let bytes = fs::read(&host_program)
        .with_context(|| format!("failed to read {}", host_program.display()))?;

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.to_string_lossy().to_string());
    argv.extend(args);

    let envp = host_environment();
    let interpreter_bytes = load_interpreter(rootfs.as_ref(), &bytes)?;
    let loaded = LoadedProgram::load_dynamic(bytes, interpreter_bytes, &argv, &envp)
        .with_context(|| format!("failed to load ELF {}", host_program.display()))?;
    let registers = Registers {
        rip: loaded.entry,
        rsp: loaded.stack_pointer,
        ..Registers::default()
    };
    let mut interpreter = Interpreter::new(loaded.memory, registers);
    interpreter.set_trace_enabled(trace);
    let mut process = LinuxProcess::with_executable(rootfs, program.to_string_lossy().to_string());

    let exit_code = run_until_exit(&mut interpreter, &mut process)?;
    if trace {
        for record in interpreter.trace() {
            println!(
                "{:#018x}: {:<32} rax={:#x}->{:#x} rbx={:#x}->{:#x} rcx={:#x}->{:#x} rdx={:#x}->{:#x} rsp={:#x}->{:#x}",
                record.ip,
                record.instruction,
                record.before.rax,
                record.after.rax,
                record.before.rbx,
                record.after.rbx,
                record.before.rcx,
                record.after.rcx,
                record.before.rdx,
                record.after.rdx,
                record.before.rsp,
                record.after.rsp
            );
        }
        for record in process.trace() {
            println!(
                "syscall {:<16} #{} args={:#x?} -> {:#x}",
                record.name, record.number, record.args, record.return_value
            );
        }
    }

    if exit_code == 0 {
        Ok(())
    } else {
        bail!("guest exited with status {exit_code}")
    }
}

fn run_until_exit(interpreter: &mut Interpreter, process: &mut LinuxProcess) -> Result<i32> {
    for _ in 0..DEFAULT_MAX_STEPS {
        match interpreter.step()? {
            StepOutcome::Continue => {}
            StepOutcome::Halted(code) => return Ok(code),
            StepOutcome::Syscall(trap) => {
                let outcome = SyscallDispatcher::dispatch(
                    process,
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
                    SyscallOutcome::Exit(code) => return Ok(code),
                }
            }
        }
    }
    bail!("guest exceeded step limit of {DEFAULT_MAX_STEPS}")
}

fn translate_program_path(rootfs: Option<&PathBuf>, program: &PathBuf) -> PathBuf {
    let Some(rootfs) = rootfs else {
        return program.clone();
    };

    let rootfs = RootFs::new(rootfs);
    match rootfs.resolve(&GuestPath::root(), &program.to_string_lossy()) {
        Ok(ResolvedPath::Host { host, .. }) => host,
        Ok(ResolvedPath::Virtual { .. }) | Err(_) => program.clone(),
    }
}

fn load_interpreter(rootfs: Option<&PathBuf>, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let image = ElfImage::parse(bytes.to_vec())?;
    let Some(path) = image.interpreter_path()? else {
        return Ok(None);
    };
    let Some(rootfs_path) = rootfs else {
        bail!("ELF requests interpreter {path}, but --rootfs was not provided");
    };
    let rootfs = RootFs::new(rootfs_path);
    let host = match rootfs.resolve(&GuestPath::root(), &path)? {
        ResolvedPath::Host { host, .. } => host,
        ResolvedPath::Virtual { .. } => bail!("ELF interpreter {path} resolved to a virtual file"),
    };
    fs::read(&host)
        .with_context(|| format!("failed to read ELF interpreter {}", host.display()))
        .map(Some)
}

fn host_environment() -> Vec<String> {
    std::env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}
