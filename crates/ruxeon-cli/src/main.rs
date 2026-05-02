use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ruxeon_core::GuestMemory;
use ruxeon_cpu::{Interpreter, Registers, StepOutcome, TraceRecord};
use ruxeon_elf::{ElfImage, LoadedProgram};
use ruxeon_fs::{GuestPath, ResolvedPath, RootFs};
use ruxeon_linux::{
    ExecveRequest, LinuxProcess, ProcessId, ProcessRecord, ProcessState, ProcessTable, Scheduler,
    SyscallContext, SyscallDispatcher, SyscallInput, SyscallOutcome,
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
    let _terminal_guard = TerminalResetGuard;
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
    let mut process_table = ProcessTable::new();
    let initial_pid = process_table.insert_initial(
        LinuxProcess::with_executable(rootfs, program.to_string_lossy().to_string()),
        loaded.memory,
        registers,
    );
    let mut scheduler = Scheduler::new();
    if let Some(record) = process_table.get(initial_pid) {
        scheduler.enqueue_process(record);
    }

    let mut trace_records = Vec::new();
    let exit_code = run_until_exit(
        &mut process_table,
        &mut scheduler,
        initial_pid,
        trace,
        &mut trace_records,
    )?;
    if trace {
        for record in &trace_records {
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
        for process_record in process_table.records().values() {
            for record in process_record.process.trace() {
                println!(
                    "pid {:<5} syscall {:<16} #{} args={:#x?} -> {:#x}",
                    process_record.process.pid(),
                    record.name,
                    record.number,
                    record.args,
                    record.return_value
                );
            }
        }
    }

    if exit_code == 0 {
        Ok(())
    } else {
        bail!("guest exited with status {exit_code}")
    }
}

struct TerminalResetGuard;

impl Drop for TerminalResetGuard {
    fn drop(&mut self) {
        ruxeon_host::reset_terminal_mode();
    }
}

fn run_until_exit(
    process_table: &mut ProcessTable,
    scheduler: &mut Scheduler,
    initial_pid: ProcessId,
    trace: bool,
    trace_records: &mut Vec<TraceRecord>,
) -> Result<i32> {
    let mut initial_exit_code = None;
    for _ in 0..DEFAULT_MAX_STEPS {
        let Some((pid, _tid)) = scheduler.next_thread(process_table) else {
            return initial_exit_code.context("no runnable guest processes remain");
        };
        let Some(mut record) = process_table.take(pid) else {
            continue;
        };
        if record.state != ProcessState::Runnable {
            process_table.insert_record(pid, record);
            continue;
        }

        let registers = record
            .main_thread_registers()
            .context("scheduled process has no main thread")?;
        let memory = std::mem::take(&mut record.memory);
        let mut interpreter = Interpreter::new(memory, registers);
        interpreter.set_trace_enabled(trace);

        match interpreter.step()? {
            StepOutcome::Continue => {}
            StepOutcome::Halted(code) => {
                process_table.record_exit(pid, record.parent, code);
                let (memory, registers, trace) = interpreter.into_parts();
                record.memory = memory;
                record.set_main_thread_registers(registers);
                record.mark_exited(code);
                trace_records.extend(trace);
                process_table.insert_record(pid, record);
                if pid == initial_pid {
                    initial_exit_code = Some(code);
                }
                continue;
            }
            StepOutcome::Syscall(trap) => {
                let registers = *interpreter.registers();
                let outcome = SyscallDispatcher::dispatch_with_process_model(
                    &mut record.process,
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
                match outcome {
                    SyscallOutcome::Return(value) => {
                        interpreter.registers_mut().rax = value as u64;
                    }
                    SyscallOutcome::Exit(code) => {
                        process_table.record_exit(pid, record.parent, code);
                        let (memory, registers, trace) = interpreter.into_parts();
                        record.memory = memory;
                        record.set_main_thread_registers(registers);
                        record.mark_exited(code);
                        trace_records.extend(trace);
                        process_table.insert_record(pid, record);
                        if pid == initial_pid {
                            initial_exit_code = Some(code);
                        }
                        enqueue_runnable(process_table, scheduler);
                        continue;
                    }
                    SyscallOutcome::Execve(request) => {
                        let (memory, registers) = execve_state(&mut record.process, request)?;
                        interpreter.replace_state(memory, registers);
                    }
                }
            }
        }

        let (memory, registers, trace) = interpreter.into_parts();
        record.memory = memory;
        record.set_main_thread_registers(registers);
        trace_records.extend(trace);
        if record.state == ProcessState::Runnable {
            sync_children(&mut record, process_table, pid);
            process_table.insert_record(pid, record);
            enqueue_runnable(process_table, scheduler);
        } else {
            sync_children(&mut record, process_table, pid);
            process_table.insert_record(pid, record);
        }
    }
    bail!("guest exceeded step limit of {DEFAULT_MAX_STEPS}")
}

fn enqueue_runnable(process_table: &ProcessTable, scheduler: &mut Scheduler) {
    for record in process_table.records().values() {
        scheduler.enqueue_process(record);
    }
}

fn sync_children(record: &mut ProcessRecord, process_table: &ProcessTable, pid: ProcessId) {
    record.children = process_table
        .records()
        .iter()
        .filter_map(|(child_pid, child)| (child.parent == Some(pid)).then_some(*child_pid))
        .collect();
}

fn execve_state(
    process: &mut LinuxProcess,
    request: ExecveRequest,
) -> Result<(GuestMemory, Registers)> {
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
    process.apply_exec(request.guest_path);
    Ok((loaded.memory, registers))
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
