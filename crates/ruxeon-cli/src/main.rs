use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ruxeon_core::GuestMemory;
use ruxeon_cpu::{
    CpuError, ExecutionCache, Interpreter, Registers, StepOutcome, TraceRecord,
    UnsupportedInstructionRecord,
};
use ruxeon_elf::{ElfImage, LoadedProgram};
use ruxeon_fs::{GuestPath, ResolvedPath, RootFs};
use ruxeon_linux::{
    ExecveRequest, LinuxProcess, ProcessId, ProcessRecord, ProcessState, ProcessTable, Scheduler,
    SyscallContext, SyscallDispatcher, SyscallInput, SyscallOutcome, ThreadId,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};
use thiserror::Error;

const DEFAULT_MAX_STEPS: u64 = 5_000_000;

#[derive(Debug, Error)]
enum RunError {
    #[error("guest step failed at pid {pid} ({program}) rip {rip:#x}")]
    GuestStep {
        pid: u32,
        program: String,
        rip: u64,
        #[source]
        source: CpuError,
    },
}

#[derive(Debug, Clone)]
struct UnsupportedInstructionEncounter {
    pid: u32,
    program: String,
    record: UnsupportedInstructionRecord,
}

#[derive(Debug, Default)]
struct UnsupportedInstructionLog {
    seen: HashSet<String>,
    entries: Vec<UnsupportedInstructionEncounter>,
}

impl UnsupportedInstructionLog {
    fn record(&mut self, pid: u32, program: &str, record: UnsupportedInstructionRecord) {
        let key = format!(
            "{program}|{}|{}",
            record.mnemonic,
            format_raw_bytes(&record.raw_bytes)
        );
        if self.seen.insert(key) {
            self.entries.push(UnsupportedInstructionEncounter {
                pid,
                program: program.to_string(),
                record,
            });
        }
    }

    fn print_summary(&self) {
        if self.entries.is_empty() {
            return;
        }
        eprintln!(
            "unsupported instructions encountered: {}",
            self.entries.len()
        );
        for entry in &self.entries {
            eprintln!("program: {}", entry.program);
            eprintln!("pid: {}", entry.pid);
            eprintln!("rip: {:#x}", entry.record.ip);
            eprintln!("bytes: {}", format_raw_bytes(&entry.record.raw_bytes));
            eprintln!("mnemonic: {}", entry.record.mnemonic);
            eprintln!("operands: {}", entry.record.operands.join(", "));
            eprintln!("instruction: {}", entry.record.text);
            eprintln!(
                "registers: rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} rbp={:#x} rsp={:#x} rip={:#x} rflags={:#x}",
                entry.record.registers.rax,
                entry.record.registers.rbx,
                entry.record.registers.rcx,
                entry.record.registers.rdx,
                entry.record.registers.rsi,
                entry.record.registers.rdi,
                entry.record.registers.rbp,
                entry.record.registers.rsp,
                entry.record.registers.rip,
                entry.record.registers.rflags
            );
        }
    }
}

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
        #[arg(long)]
        trace: bool,
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
            trace,
            program,
            args,
        } => run_program(rootfs, program, args, trace),
        Command::Shell { rootfs } => {
            run_program(Some(rootfs), PathBuf::from("/bin/sh"), Vec::new(), false)
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
    let mut execution_caches = HashMap::new();
    execution_caches.insert(initial_pid, ExecutionCache::default());
    let mut unsupported_log = UnsupportedInstructionLog::default();

    let mut trace_records = Vec::new();
    let exit_code = run_until_exit(
        &mut process_table,
        &mut scheduler,
        &mut execution_caches,
        &mut unsupported_log,
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
    execution_caches: &mut HashMap<ProcessId, ExecutionCache>,
    unsupported_log: &mut UnsupportedInstructionLog,
    initial_pid: ProcessId,
    trace: bool,
    trace_records: &mut Vec<TraceRecord>,
) -> Result<i32> {
    let mut initial_exit_code = None;
    let mut last_step_context: Option<(u32, String, u64)> = None;
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
        let cache = execution_caches.remove(&pid).unwrap_or_default();
        let mut interpreter = Interpreter::with_cache(memory, registers, cache);
        interpreter.set_trace_enabled(trace);

        let step_rip = interpreter.registers().rip;
        last_step_context = Some((
            pid.0,
            record.process.executable_path().to_string(),
            step_rip,
        ));
        let step = match interpreter.step_block() {
            Ok(step) => step,
            Err(source) => {
                let program = record.process.executable_path().to_string();
                if let Some(unsupported) = source.unsupported_instruction().cloned() {
                    unsupported_log.record(pid.0, &program, unsupported);
                    unsupported_log.print_summary();
                }
                if trace {
                    eprintln!("recent guest instructions before failure:");
                    for record in trace_records.iter().rev().take(64).rev() {
                        eprintln!(
                            "{:#018x}: {:<32} rax={:#x}->{:#x} rbx={:#x}->{:#x} rcx={:#x}->{:#x} rdx={:#x}->{:#x} rsi={:#x}->{:#x} rdi={:#x}->{:#x} rsp={:#x}->{:#x}",
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
                            record.before.rsi,
                            record.after.rsi,
                            record.before.rdi,
                            record.after.rdi,
                            record.before.rsp,
                            record.after.rsp
                        );
                    }
                    eprintln!("current block before failure:");
                    for record in interpreter.trace().iter().rev().take(32).rev() {
                        eprintln!(
                            "{:#018x}: {:<32} rax={:#x}->{:#x} rbx={:#x}->{:#x} rcx={:#x}->{:#x} rdx={:#x}->{:#x} rsi={:#x}->{:#x} rdi={:#x}->{:#x} rsp={:#x}->{:#x}",
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
                            record.before.rsi,
                            record.after.rsi,
                            record.before.rdi,
                            record.after.rdi,
                            record.before.rsp,
                            record.after.rsp
                        );
                    }
                }
                return Err(RunError::GuestStep {
                    pid: pid.0,
                    program,
                    rip: step_rip,
                    source,
                }
                .into());
            }
        };
        match step {
            StepOutcome::Continue => {}
            StepOutcome::Halted(code) => {
                process_table.record_exit(pid, record.parent, code);
                let (memory, registers, trace, cache) = interpreter.into_state();
                record.memory = memory;
                record.set_main_thread_registers(registers);
                record.mark_exited(code);
                trace_records.extend(trace);
                execution_caches.insert(pid, cache);
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
                interpreter.clear_block_cache();
                interpreter.registers_mut().fs_base = record.process.fs_base();
                match outcome {
                    SyscallOutcome::Return(value) => {
                        interpreter.registers_mut().rax = value as u64;
                    }
                    SyscallOutcome::Blocked => {
                        let (memory, registers, trace, cache) = interpreter.into_state();
                        record.memory = memory;
                        record.set_main_thread_registers(registers);
                        record.state = ProcessState::Waiting;
                        if let Some(thread) =
                            record.threads.get_mut(&ThreadId(record.process.tid()))
                        {
                            thread.state = ProcessState::Waiting;
                        }
                        trace_records.extend(trace);
                        execution_caches.insert(pid, cache);
                        sync_children(&mut record, process_table, pid);
                        process_table.insert_record(pid, record);
                        enqueue_runnable(process_table, scheduler);
                        continue;
                    }
                    SyscallOutcome::Exit(code) => {
                        process_table.record_exit(pid, record.parent, code);
                        let (memory, registers, trace, cache) = interpreter.into_state();
                        record.memory = memory;
                        record.set_main_thread_registers(registers);
                        record.mark_exited(code);
                        trace_records.extend(trace);
                        execution_caches.insert(pid, cache);
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

        let (memory, registers, trace, cache) = interpreter.into_state();
        record.memory = memory;
        record.set_main_thread_registers(registers);
        trace_records.extend(trace);
        execution_caches.insert(pid, cache);
        if record.state == ProcessState::Runnable {
            sync_children(&mut record, process_table, pid);
            process_table.insert_record(pid, record);
            enqueue_runnable(process_table, scheduler);
        } else {
            sync_children(&mut record, process_table, pid);
            process_table.insert_record(pid, record);
        }
    }
    if let Some((pid, program, rip)) = last_step_context {
        bail!(
            "guest exceeded step limit of {DEFAULT_MAX_STEPS} at pid {pid} ({program}) rip {rip:#x}"
        );
    }
    bail!("guest exceeded step limit of {DEFAULT_MAX_STEPS}")
}

fn format_raw_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
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
    let mut env = Vec::new();
    let mut has_path = false;
    for (key, value) in std::env::vars() {
        if key.eq_ignore_ascii_case("PATH") {
            has_path = true;
            env.push(format!(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ));
        } else {
            env.push(format!("{key}={value}"));
        }
    }
    if !has_path {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    }
    env
}
