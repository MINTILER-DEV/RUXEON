use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ruxeon_cpu::{Interpreter, Registers, StepOutcome};
use ruxeon_elf::{ElfImage, LoadedProgram};
use ruxeon_fs::{GuestPath, ResolvedPath, RootFs};
use ruxeon_linux::{
    ExecveRequest, LinuxProcess, ProcessTable, Scheduler, SyscallContext, SyscallDispatcher,
    SyscallInput, SyscallOutcome,
};
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
    let loaded = load_program_image(rootfs.as_ref(), bytes, &argv, &envp)
        .with_context(|| format!("failed to load ELF {}", host_program.display()))?;
    let registers = Registers {
        rip: loaded.entry,
        rsp: loaded.stack_pointer,
        ..Registers::default()
    };
    let mut interpreter = Interpreter::new(loaded.memory, registers);
    interpreter.set_trace_enabled(trace);
    let mut process =
        LinuxProcess::with_executable(rootfs.clone(), program.to_string_lossy().to_string());
    let mut process_table = ProcessTable::new();
    let initial_pid = process_table.insert_initial(
        LinuxProcess::with_executable(rootfs, program.to_string_lossy().to_string()),
        interpreter.memory().clone(),
        *interpreter.registers(),
    );
    let mut scheduler = Scheduler::new();
    if let Some(record) = process_table.get(initial_pid) {
        scheduler.enqueue_process(record);
    }

    let exit_code = run_until_exit(
        &mut interpreter,
        &mut process,
        &mut process_table,
        &mut scheduler,
    )?;
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

fn run_until_exit(
    interpreter: &mut Interpreter,
    process: &mut LinuxProcess,
    process_table: &mut ProcessTable,
    scheduler: &mut Scheduler,
) -> Result<i32> {
    for _ in 0..DEFAULT_MAX_STEPS {
        match interpreter.step()? {
            StepOutcome::Continue => {}
            StepOutcome::Halted(code) => return Ok(code),
            StepOutcome::Syscall(trap) => {
                let registers = *interpreter.registers();
                let outcome = SyscallDispatcher::dispatch_with_process_model(
                    process,
                    &mut SyscallContext {
                        memory: interpreter.memory_mut(),
                    },
                    SyscallInput {
                        number: trap.number,
                        args: trap.args,
                    },
                    Some(process_table),
                    Some(registers),
                );
                if let Some(record) = process_table.records().values().last() {
                    scheduler.enqueue_process(record);
                }
                match outcome {
                    SyscallOutcome::Return(value) => {
                        interpreter.registers_mut().rax = value as u64;
                    }
                    SyscallOutcome::Exit(code) => return Ok(code),
                    SyscallOutcome::Execve(request) => {
                        execve(interpreter, process, request)?;
                    }
                }
            }
        }
    }
    bail!("guest exceeded step limit of {DEFAULT_MAX_STEPS}")
}

fn execve(
    interpreter: &mut Interpreter,
    process: &mut LinuxProcess,
    request: ExecveRequest,
) -> Result<()> {
    let bytes = fs::read(&request.host_path).with_context(|| {
        format!(
            "failed to read execve target {}",
            request.host_path.display()
        )
    })?;
    let loaded = load_program_image(request.rootfs.as_ref(), bytes, &request.argv, &request.envp)
        .with_context(|| {
        format!(
            "failed to load execve target {}",
            request.host_path.display()
        )
    })?;
    let registers = Registers {
        rip: loaded.entry,
        rsp: loaded.stack_pointer,
        ..Registers::default()
    };
    interpreter.replace_state(loaded.memory, registers);
    process.apply_exec(request.guest_path);
    Ok(())
}

fn load_program_image(
    rootfs: Option<&PathBuf>,
    bytes: Vec<u8>,
    argv: &[String],
    envp: &[String],
) -> Result<LoadedProgram> {
    let interpreter_bytes = load_interpreter(rootfs, &bytes)?;
    LoadedProgram::load_dynamic(bytes, interpreter_bytes, argv, envp).map_err(Into::into)
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
