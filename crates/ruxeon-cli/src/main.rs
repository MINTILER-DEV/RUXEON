use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ruxeon_cpu::{Interpreter, Registers, RunOutcome};
use ruxeon_elf::LoadedProgram;
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
    let loaded = LoadedProgram::load(bytes, &argv, &envp)
        .with_context(|| format!("failed to load ELF {}", host_program.display()))?;
    let registers = Registers {
        rip: loaded.entry,
        rsp: loaded.stack_pointer,
        ..Registers::default()
    };
    let mut interpreter = Interpreter::new(loaded.memory, registers);
    interpreter.set_trace_enabled(trace);

    let outcome = interpreter.run(DEFAULT_MAX_STEPS)?;
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
    }

    match outcome {
        RunOutcome::Exited(code) => {
            if code == 0 {
                Ok(())
            } else {
                bail!("guest exited with status {code}")
            }
        }
        RunOutcome::Syscall(trap) => bail!(
            "unsupported Linux syscall {} args={:#x?}",
            trap.number,
            trap.args
        ),
        RunOutcome::StepLimit => bail!("guest exceeded step limit of {DEFAULT_MAX_STEPS}"),
    }
}

fn translate_program_path(rootfs: Option<&PathBuf>, program: &PathBuf) -> PathBuf {
    let Some(rootfs) = rootfs else {
        return program.clone();
    };

    let guest_path = program.to_string_lossy().replace('\\', "/");
    if guest_path.starts_with('/') {
        let relative = guest_path
            .trim_start_matches('/')
            .split('/')
            .filter(|part| !part.is_empty() && *part != "." && *part != "..")
            .collect::<PathBuf>();
        rootfs.join(relative)
    } else {
        rootfs.join(program)
    }
}

fn host_environment() -> Vec<String> {
    std::env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}
